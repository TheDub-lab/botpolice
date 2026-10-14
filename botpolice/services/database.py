"""Fake database port.

Accepts the TCP connection, reads the first bytes (bounded), logs them, and
closes. It never speaks a database protocol and never parses a query.
"""

from __future__ import annotations

import asyncio

from .common import ServiceContext, peer, read_first


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ctx: ServiceContext,
) -> None:
    async with ctx.limiter:
        src_ip, src_port = peer(writer.get_extra_info("peername"))
        sockname = writer.get_extra_info("sockname")
        dst_port = int(sockname[1]) if isinstance(sockname, (tuple, list)) else None

        data = await read_first(
            reader, ctx.limits.max_read_bytes, ctx.limits.per_connection_timeout_seconds
        )

        ctx.sink.record(
            event="database_connection",
            service="database",
            severity="medium",
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            summary=f"database port probed from {src_ip}",
            raw=data,
        )

        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def start_database(ctx: ServiceContext, host: str, port: int) -> asyncio.AbstractServer:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle(reader, writer, ctx)

    return await asyncio.start_server(handler, host, port, limit=65536)
