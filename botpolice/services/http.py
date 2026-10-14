"""Fake admin web panel.

A minimal HTTP/1.1 responder (no framework needed for the core listener). It
serves a plausible login page and a handful of juicy-looking paths, logs every
request in full, and flags any request carrying a known canary token or hitting
a ``/t/<token>`` tripwire.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from .common import ServiceContext, peer
from .httpio import build_response, decode, local_port, read_request, send_raw

_FAKE_LOGIN = """<!doctype html>
<html><head><title>Admin Console - Sign in</title></head>
<body>
<h1>Administrator Login</h1>
<form method="post" action="/admin/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Sign in</button>
</form>
<p>Authorized personnel only.</p>
</body></html>
"""

_FAKE_ENV = """# .env - internal service configuration (DECOY, values are not real)
APP_ENV=production
SECRET_KEY=not-a-real-secret-8f2a
DATABASE_URL=postgresql://app:fake-password@db-internal:5432/app
SENTRY_DSN=https://example@example.invalid/000000
INTERNAL_ADMIN={base}/admin
CANARY={base}/t/{token}
"""

_FAKE_CONFIG_JSON = """{{
  "application": "internal-portal",
  "debug": false,
  "database": {{
    "host": "db-internal",
    "port": 5432,
    "user": "admin",
    "password": "this-is-a-decoy-not-a-password"
  }},
  "api": {{
    "base_url": "{base}/api",
    "canary_url": "{base}/t/{token}"
  }}
}}
"""

_FAKE_BACKUP = (
    b"PK\x03\x04 (decoy archive header)\n"
    b"backup-2026-10-13.tar.gz - simulated contents, not a real backup\n"
)

_RESPONSES = {
    "/": (200, "OK", "text/html; charset=utf-8", _FAKE_LOGIN),
    "/admin": (200, "OK", "text/html; charset=utf-8", _FAKE_LOGIN),
    "/admin/login": (200, "OK", "text/html; charset=utf-8", _FAKE_LOGIN),
    "/.env": (200, "OK", "text/plain; charset=utf-8", _FAKE_ENV),
    "/config.json": (200, "OK", "application/json", _FAKE_CONFIG_JSON),
}


def _render(body: str, ctx: ServiceContext, token: str = "none") -> str:
    return body.format(base=ctx.http_url, token=token)


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
            matched_token = None
            if ctx.matcher is not None:
                match = ctx.matcher(decode(request.raw))
                if match is not None:
                    placement = match.placement
                    matched_token = match.token

            is_tripwire = path.startswith("/t/")
            token_in_path = path[len("/t/") :] if is_tripwire else ""

            if is_tripwire:
                severity, event = "high", "tripwire_hit"
                summary = f"tripwire hit {request.method} {path}"
            elif placement:
                severity, event = "high", "canary_token_used"
                summary = f"canary token used in {request.method} {request.target}"
            else:
                severity, event = "medium", "http_request"
                summary = f"{request.method} {request.target}"

            ctx.sink.record(
                event=event,
                service="http",
                severity=severity,
                src_ip=src_ip,
                src_port=src_port,
                dst_port=dst_port,
                placement=placement,
                summary=summary,
                raw=request.raw,
                extra={
                    "method": request.method,
                    "path": path,
                    "matched_token": matched_token,
                },
            )

            await _respond(writer, path, ctx, token_in_path)
        except (ConnectionError, OSError):
            return
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def _respond(
    writer: asyncio.StreamWriter,
    path: str,
    ctx: ServiceContext,
    token_in_path: str,
) -> None:
    if path.startswith("/t/"):
        body = _render("<!doctype html><html><body>ok</body></html>", ctx)
        await send_raw(writer, build_response(200, "OK", "text/html; charset=utf-8", body))
    elif path == "/backup" or path.startswith("/backup/") or path.startswith("/backups"):
        await send_raw(
            writer, build_response(200, "OK", "application/octet-stream", _FAKE_BACKUP)
        )
    else:
        status, reason, content_type, body = _RESPONSES.get(
            path,
            (404, "Not Found", "text/html; charset=utf-8", "<html><body>404 Not Found</body></html>"),
        )
        await send_raw(
            writer,
            build_response(status, reason, content_type, _render(body, ctx, token_in_path or "none")),
        )


async def start_http(ctx: ServiceContext, host: str, port: int) -> asyncio.AbstractServer:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle(reader, writer, ctx)

    return await asyncio.start_server(handler, host, port, limit=65536)
