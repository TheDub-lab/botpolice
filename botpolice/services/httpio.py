"""Minimal, allocation-bounded HTTP/1.x request parsing shared by decoys."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .common import read_until


def decode(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def parse_head(head: bytes) -> tuple[str, str, str, dict[str, str]]:
    lines = head.split(b"\r\n")
    request_line = decode(lines[0]) if lines and lines[0] else ""
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[decode(key).strip().lower()] = decode(value).strip()
    return method, target, version, headers


def content_length(headers: dict[str, str]) -> int:
    try:
        return max(0, int(headers.get("content-length", "0")))
    except ValueError:
        return 0


async def read_body(reader: asyncio.StreamReader, length: int, timeout: float) -> bytes:
    buf = bytearray()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while len(buf) < length:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(4096, length - len(buf))), timeout=remaining
            )
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict[str, str]
    body: bytes
    raw: bytes


async def read_request(
    reader: asyncio.StreamReader,
    max_header_bytes: int,
    max_body_bytes: int,
    timeout: float,
) -> HttpRequest | None:
    raw_head = await read_until(reader, b"\r\n\r\n", max_header_bytes, timeout)
    if not raw_head:
        return None
    head, sep, leftover = raw_head.partition(b"\r\n\r\n")
    method, target, version, headers = parse_head(head)

    length = min(content_length(headers), max_body_bytes)
    body = leftover[:length]
    if len(body) < length:
        body += await read_body(reader, length - len(body), timeout)

    return HttpRequest(
        method=method,
        target=target,
        version=version,
        headers=headers,
        body=body,
        raw=head + (sep or b"\r\n\r\n") + body,
    )


def build_response(
    status: int,
    reason: str,
    content_type: str,
    body: str | bytes,
    server: str = "nginx/1.24.0",
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    payload = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    header_lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Server: {server}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(payload)}",
        "Connection: close",
    ]
    if extra_headers:
        header_lines.extend(f"{k}: {v}" for k, v in extra_headers.items())
    head = ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8")
    return head + payload


async def send_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
    try:
        writer.write(data)
        await writer.drain()
    except (ConnectionError, OSError):
        pass


def local_port(writer: asyncio.StreamWriter) -> int | None:
    sockname = writer.get_extra_info("sockname")
    if isinstance(sockname, (tuple, list)) and len(sockname) >= 2:
        return int(sockname[1])
    return None
