"""Shared helpers for the decoy services: bounded reads and connection limits."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import DEFAULT_ADB_IDENTITY, Config, Limits
from ..sink import EventSink


class ConnectionLimiter:
    """A shared asyncio semaphore bounding concurrent connections."""

    def __init__(self, limit: int) -> None:
        self._sem = asyncio.Semaphore(max(1, limit))

    async def __aenter__(self) -> ConnectionLimiter:
        await self._sem.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._sem.release()


@dataclass
class ServiceContext:
    sink: EventSink
    limits: Limits
    limiter: ConnectionLimiter = field(default_factory=lambda: ConnectionLimiter(64))
    matcher: Callable[[str], Any] | None = None
    http_url: str = "http://127.0.0.1:8080"
    log: Any | None = None
    ssh_banner: bytes | None = None
    http_server: str = "nginx/1.24.0"
    adb_identity: dict[str, str] | None = None


async def read_first(reader: asyncio.StreamReader, max_bytes: int, timeout: float) -> bytes:
    """Read up to ``max_bytes`` (or EOF), never blocking past ``timeout``."""
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data or b""
    except (TimeoutError, OSError):
        return b""


async def read_until(
    reader: asyncio.StreamReader,
    delimiter: bytes,
    max_bytes: int,
    timeout: float,
) -> bytes:
    """Read until ``delimiter`` appears, EOF, ``max_bytes``, or ``timeout``."""
    buf = bytearray()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while delimiter not in buf:
        if len(buf) >= max_bytes:
            break
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        want = min(4096, max_bytes - len(buf))
        try:
            chunk = await asyncio.wait_for(reader.read(want), timeout=remaining)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def peer(addr: Any) -> tuple[str | None, int | None]:
    if isinstance(addr, (tuple, list)) and len(addr) >= 2:
        return str(addr[0]), int(addr[1])
    return None, None


def build_context(config: Config) -> ServiceContext:
    """Build the shared service context (sink, limiter, matcher) from config."""
    from ..alerting import build_alerter
    from ..canary import CanaryStore
    from ..decoys import resolve_identity
    from ..eventlog import EventLog

    log = EventLog(config.resolve(config.log_path))
    alerter = build_alerter(config.alerts)
    sink = EventSink(log, alerter=alerter, limits=config.limits)
    limiter = ConnectionLimiter(config.limits.max_connections)
    matcher = CanaryStore(config.resolve(config.canary_store)).match

    profile = resolve_identity(config)
    adb_identity = config.adb.identity
    if adb_identity == DEFAULT_ADB_IDENTITY:
        adb_identity = profile.adb_identity

    return ServiceContext(
        sink=sink,
        limits=config.limits,
        limiter=limiter,
        matcher=matcher,
        http_url=config.listener_url(),
        log=log,
        ssh_banner=profile.ssh_banner.encode("ascii", "replace"),
        http_server=profile.http_server,
        adb_identity=adb_identity,
    )


async def start_all(
    config: Config, ctx: ServiceContext | None = None
) -> list[tuple[str, asyncio.AbstractServer]]:
    """Start every enabled decoy service. Returns ``[(name, server), ...]``."""
    from functools import partial

    from . import adb, compute, database, http, ssh

    if ctx is None:
        ctx = build_context(config)

    starters: dict[str, Callable[..., Any]] = {
        "ssh": partial(ssh.start_ssh, banner=ctx.ssh_banner),
        "http": http.start_http,
        "compute": compute.start_compute,
        "database": database.start_database,
        "adb": partial(
            adb.start_adb,
            config=config.adb,
            data=adb.AdbData.load(
                config.resolve(config.adb.responses_file),
                ctx.adb_identity or config.adb.identity,
            ),
        ),
    }

    servers: list[tuple[str, asyncio.AbstractServer]] = []
    for name, start in starters.items():
        svc = config.services.get(name)
        if svc is None or not svc.enabled:
            continue
        host = config.bind
        if name == "adb" and config.adb.bind:
            host = config.adb.bind
        server = await start(ctx, host, svc.port)
        servers.append((name, server))
    return servers


async def stop_all(servers: list[tuple[str, asyncio.AbstractServer]]) -> None:
    for _name, server in servers:
        server.close()
    for _name, server in servers:
        with contextlib.suppress(OSError):
            await server.wait_closed()
