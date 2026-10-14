import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from botpolice.config import Limits
from botpolice.services.common import ConnectionLimiter, ServiceContext
from botpolice.services.compute import start_compute
from botpolice.services.database import start_database
from botpolice.services.ssh import start_ssh

from helpers import MatchRecorder, make_sink, read_all, server_port


class ServiceTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sink, self.log = make_sink(Path(self.tmp.name))
        self.matcher = MatchRecorder()
        self.ctx = ServiceContext(
            sink=self.sink,
            limits=Limits(),
            limiter=ConnectionLimiter(16),
            matcher=self.matcher,
            http_url="http://127.0.0.1:8080",
        )
        self.servers = []
        self.addAsyncCleanup(self._stop)

    def _track(self, server) -> None:
        self.servers.append(server)

    async def _stop(self) -> None:
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()


class SshDecoyTests(ServiceTestCase):
    async def test_banner_and_hit_logged(self) -> None:
        server = await start_ssh(self.ctx, "127.0.0.1", 0)
        self._track(server)
        port = server_port(server)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        banner = await asyncio.wait_for(reader.readline(), timeout=5)
        self.assertTrue(banner.startswith(b"SSH-2.0-"))
        writer.write(b"SSH-2.0-evil-scanner\r\n")
        await writer.drain()
        data = await read_all(reader)
        self.assertEqual(data, b"")
        writer.close()

        entries = list(self.log.read_all())
        entry = entries[-1]
        self.assertEqual(entry["event"], "ssh_connection")
        self.assertEqual(entry["service"], "ssh")
        self.assertEqual(entry["src_ip"], "127.0.0.1")
        self.assertEqual(entry["dst_port"], port)
        self.assertIn("evil-scanner", entry["raw"])


class ComputeDecoyTests(ServiceTestCase):
    async def _request(self, port: int, path: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await read_all(reader)
        writer.close()
        return data

    async def test_tags_returns_models_and_alerts(self) -> None:
        server = await start_compute(self.ctx, "127.0.0.1", 0)
        self._track(server)
        port = server_port(server)

        data = await self._request(port, "/api/tags")
        text = data.decode("latin-1")
        self.assertIn("200 OK", text)
        body = text.split("\r\n\r\n", 1)[1]
        payload = json.loads(body)
        self.assertTrue(payload["models"])
        self.assertIn("llama3.1:8b", [m["name"] for m in payload["models"]])

        entry = list(self.log.read_all())[-1]
        self.assertEqual(entry["event"], "compute_bait_hit")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["service"], "compute")

    async def test_generate_returns_canned_response(self) -> None:
        server = await start_compute(self.ctx, "127.0.0.1", 0)
        self._track(server)
        port = server_port(server)

        data = await self._request(port, "/api/generate")
        body = data.decode("latin-1").split("\r\n\r\n", 1)[1]
        payload = json.loads(body)
        self.assertTrue(payload["done"])
        self.assertIn("decoy", payload["response"])
        self.assertEqual(list(self.log.read_all())[-1]["severity"], "high")


class DatabaseDecoyTests(ServiceTestCase):
    async def test_connect_and_first_bytes_logged(self) -> None:
        server = await start_database(self.ctx, "127.0.0.1", 0)
        self._track(server)
        port = server_port(server)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x00\x00\x00\x2f\x04\xd2\x16\x2f")
        await writer.drain()
        await read_all(reader)
        writer.close()

        entry = list(self.log.read_all())[-1]
        self.assertEqual(entry["event"], "database_connection")
        self.assertEqual(entry["service"], "database")
        self.assertEqual(entry["severity"], "medium")
        self.assertGreater(entry["raw_len"], 0)


if __name__ == "__main__":
    unittest.main()
