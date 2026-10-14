"""Fake open LLM inference API (Ollama-style).

Every request is an alert: something is looking for model-inference capacity.
The endpoint returns canned JSON only. No model is loaded and no received input
is ever executed or interpreted beyond routing on the URL path.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit

from .common import ServiceContext, peer
from .httpio import build_response, decode, local_port, read_request, send_raw

_MODELS = [
    "llama3.1:8b",
    "qwen2.5:7b",
    "mistral:7b",
    "nomic-embed-text:latest",
]

_TAGS = {"models": [{"name": name, "model": name, "size": 4700000000} for name in _MODELS]}


def _generate_response() -> dict:
    return {
        "model": "llama3.1:8b",
        "created_at": "2026-10-13T00:00:00Z",
        "response": "This endpoint is a decoy and does not run a model.",
        "done": True,
        "context": [1, 2, 3],
    }


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ctx: ServiceContext,
) -> None:
    async with ctx.limiter:
        src_ip, src_port = peer(writer.get_extra_info("peername"))
        dst_port = local_port(writer)
        try:
            request = await read_request(
                reader,
                ctx.limits.max_header_bytes,
                ctx.limits.max_read_bytes,
                ctx.limits.per_connection_timeout_seconds,
            )
            if request is None:
                return

            path = urlsplit(request.target).path
            placement = None
            if ctx.matcher is not None:
                match = ctx.matcher(decode(request.raw))
                if match is not None:
                    placement = match.placement

            ctx.sink.record(
                event="compute_bait_hit",
                service="compute",
                severity="high",
                src_ip=src_ip,
                src_port=src_port,
                dst_port=dst_port,
                placement=placement,
                summary=f"compute bait used: {request.method} {request.target}",
                raw=request.raw,
                extra={"method": request.method, "path": path},
            )

            await _respond(writer, request.method, path)
        except (ConnectionError, OSError):
            return
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def _respond(writer: asyncio.StreamWriter, method: str, path: str) -> None:
    if path == "/api/tags":
        body = json.dumps(_TAGS)
        await send_raw(writer, build_response(200, "OK", "application/json", body))
    elif path == "/api/generate":
        body = json.dumps(_generate_response())
        await send_raw(writer, build_response(200, "OK", "application/json", body))
    elif path == "/api/chat":
        body = json.dumps({"model": "llama3.1:8b", "message": {"role": "assistant", "content": "decoy"}, "done": True})
        await send_raw(writer, build_response(200, "OK", "application/json", body))
    elif path == "/":
        await send_raw(
            writer, build_response(200, "OK", "text/plain; charset=utf-8", "Ollama is running")
        )
    else:
        await send_raw(
            writer, build_response(404, "Not Found", "application/json", '{"error":"not found"}')
        )


async def start_compute(ctx: ServiceContext, host: str, port: int) -> asyncio.AbstractServer:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle(reader, writer, ctx)

    return await asyncio.start_server(handler, host, port, limit=65536)
