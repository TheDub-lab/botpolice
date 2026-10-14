import asyncio
import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from botpolice.canary import CanaryStore
from botpolice.config import load_config_with_source
from botpolice.eventlog import verify_log
from botpolice.server import run
from botpolice.services.common import start_all, stop_all

from helpers import read_all, server_port


def _write_config(root: Path) -> Path:
    config = {
        "bind": "127.0.0.1",
        "log_path": "events.jsonl",
        "canary_store": "canaries.json",
        "canary_output_dir": "canaries",
        "services": {
            "ssh": {"enabled": True, "port": 0},
            "http": {"enabled": True, "port": 0},
            "compute": {"enabled": True, "port": 0},
            "database": {"enabled": True, "port": 0},
            "adb": {"enabled": True, "port": 0},
        },
        "alerts": {"min_severity": "info", "webhook_url": None},
    }
    path = root / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def _read_events(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class StartAllTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_path = _write_config(self.root)
        self.config, _ = load_config_with_source(self.config_path)
        self.servers = []
        self.addAsyncCleanup(self._stop)

    async def _stop(self) -> None:
        if self.servers:
            await stop_all(self.servers)

    async def test_canary_tripwire_and_ssh_hits_are_logged(self) -> None:
        store = CanaryStore(self.config.resolve(self.config.canary_store))
        record = store.generate(
            "lab", "tripwire", "http://127.0.0.1:8080", self.config.resolve(self.config.canary_output_dir)
        )

        self.servers = await start_all(self.config)
        ports = {name: server_port(server) for name, server in self.servers}
        self.assertEqual(set(ports), {"ssh", "http", "compute", "database", "adb"})

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        writer.write(f"GET /t/{record.token} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        await read_all(reader)
        writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["ssh"])
        writer.write(b"SSH-2.0-scanner\r\n")
        await writer.drain()
        await read_all(reader)
        writer.close()

        events = _read_events(self.config.resolve(self.config.log_path))
        tripwire = [e for e in events if e["event"] == "tripwire_hit"]
        self.assertTrue(tripwire)
        self.assertEqual(tripwire[-1]["placement"], "lab")
        self.assertEqual(tripwire[-1]["severity"], "high")
        self.assertTrue(any(e["event"] == "ssh_connection" for e in events))
        self.assertTrue(verify_log(self.config.resolve(self.config.log_path)).ok)


class RunLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_logs_start_and_stop_and_is_cancellable(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        config_path = _write_config(root)
        config, _ = load_config_with_source(config_path)

        ready: asyncio.Future = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(run(config, ready))
        info = await asyncio.wait_for(ready, timeout=5)
        self.assertEqual(set(info["ports"]), {"ssh", "http", "compute", "database", "adb"})

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        events = _read_events(config.resolve(config.log_path))
        kinds = [e["event"] for e in events]
        self.assertIn("listener_started", kinds)
        self.assertIn("listener_stopped", kinds)


if __name__ == "__main__":
    unittest.main()
