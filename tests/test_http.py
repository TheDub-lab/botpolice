import asyncio
import contextlib
import tempfile
import unittest
from pathlib import Path

from botpolice.config import Limits
from botpolice.services.common import ConnectionLimiter, ServiceContext
from botpolice.services.http import start_http

from helpers import MatchRecorder, make_sink, server_port


async def _http_get(port: int, path: str, extra: bytes = b"") -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    request = (
        f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + extra
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return data


class HttpDecoyTests(unittest.IsolatedAsyncioTestCase):
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
        self.server = await start_http(self.ctx, "127.0.0.1", 0)
        self.addAsyncCleanup(self._stop)

    async def _stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def test_env_endpoint_returns_decoy_and_logs(self) -> None:
        port = server_port(self.server)
        data = await _http_get(port, "/.env")
        text = data.decode("latin-1")
        self.assertIn("200 OK", text)
        self.assertIn("DECOY", text)
        self.assertIn("DATABASE_URL", text)

        entries = list(self.log.read_all())
        self.assertTrue(entries)
        entry = entries[-1]
        self.assertEqual(entry["service"], "http")
        self.assertEqual(entry["event"], "http_request")
        self.assertEqual(entry["dst_port"], port)

    async def test_every_request_is_logged_fully(self) -> None:
        port = server_port(self.server)
        await _http_get(port, "/admin")
        entries = list(self.log.read_all())
        self.assertTrue(any("/admin" in (e.get("summary") or "") for e in entries))

    async def test_unknown_path_returns_404(self) -> None:
        port = server_port(self.server)
        data = await _http_get(port, "/does-not-exist")
        self.assertIn("404", data.decode("latin-1"))

    async def test_canary_token_in_request_raises_high_severity(self) -> None:
        port = server_port(self.server)
        await _http_get(port, "/api?key=canarytoken")
        entries = list(self.log.read_all())
        entry = entries[-1]
        self.assertEqual(entry["event"], "canary_token_used")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["placement"], "lab")

    async def test_tripwire_hit_is_high_severity(self) -> None:
        port = server_port(self.server)
        await _http_get(port, "/t/canarytoken")
        entries = list(self.log.read_all())
        entry = entries[-1]
        self.assertEqual(entry["event"], "tripwire_hit")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["placement"], "lab")

    async def test_large_body_is_capped(self) -> None:
        port = server_port(self.server)
        body = b"A" * 20000
        request = (
            f"POST /admin/login HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + body
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

        entry = list(self.log.read_all())[-1]
        self.assertTrue(entry["truncated"])
        self.assertLessEqual(len(entry["raw"].encode("utf-8")), self.ctx.limits.payload_cap_bytes)
        self.assertGreater(entry["raw_len"], self.ctx.limits.payload_cap_bytes)

    async def test_body_is_read_and_logged(self) -> None:
        port = server_port(self.server)
        body = b"username=admin&password=canarytoken"
        request = (
            f"POST /admin/login HTTP/1.1\r\nHost: localhost\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + body
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

        entries = list(self.log.read_all())
        entry = entries[-1]
        self.assertEqual(entry["event"], "canary_token_used")
        self.assertEqual(entry["placement"], "lab")


if __name__ == "__main__":
    unittest.main()
