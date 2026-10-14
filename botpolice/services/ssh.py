"""Fake SSH banner service.

Greets the client with a plausible banner, reads whatever it sends (bounded),
logs it, and closes. There is no authentication, no key exchange, and no shell.
"""

from __future__ import annotations

import asyncio

from .common import ServiceContext, peer, read_first

BANNER = b"SSH-2.0-OpenSSH_9.8\r\n"


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ctx: ServiceContext,
    banner: bytes,
) -> None:
    async with ctx.limiter:
        src_ip, src_port = peer(writer.get_extra_info("peername"))
        timeout = ctx.limits.per_connection_timeout_seconds
        dst_port = writer.get_extra_info("sockname")
        dst_port = int(dst_port[1]) if isinstance(dst_port, (tuple, list)) else None
        try:
            writer.write(banner)
            await writer.drain()
        except (ConnectionError, OSError):
            pass

        data = await read_first(reader, ctx.limits.max_read_bytes, timeout)

        ctx.sink.record(
            event="ssh_connection",
            service="ssh",
            severity="medium",
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            summary=f"SSH client connected from {src_ip}",
            raw=data,
        )

        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def start_ssh(
    ctx: ServiceContext, host: str, port: int, banner: bytes | None = None
) -> asyncio.AbstractServer:
    line = banner or BANNER

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle(reader, writer, ctx, line)

    return await asyncio.start_server(handler, host, port, limit=65536)
