"""Async listener orchestrator: start decoys, wait, shut down cleanly."""

from __future__ import annotations

import asyncio
import contextlib
import signal
from typing import Any

from .config import Config
from .services.common import build_context, start_all, stop_all


def _bound_ports(servers: list[tuple[str, asyncio.AbstractServer]]) -> dict[str, int]:
    ports: dict[str, int] = {}
    for name, server in servers:
        sockets = getattr(server, "sockets", None)
        if sockets:
            ports[name] = int(sockets[0].getsockname()[1])
    return ports


async def run(config: Config, ready: asyncio.Future | None = None) -> dict[str, Any]:
    """Run decoy services until cancelled or signalled. Returns a summary."""
    ctx = build_context(config)
    servers = await start_all(config, ctx)
    ports = _bound_ports(servers)

    dashboard = None
    if config.dashboard.enabled:
        from .dashboard import start_dashboard

        dashboard = start_dashboard(config)

    ctx.sink.record(
        event="listener_started",
        service="botpolice",
        severity="info",
        summary="decoy listeners started",
        extra={"bind": config.bind, "ports": ports},
    )
    for name, port in ports.items():
        print(f"botpolice: {name} decoy listening on {config.bind}:{port}", flush=True)

    if not ports:
        print("botpolice: warning: no services enabled", flush=True)

    if ready is not None and not ready.done():
        ready.set_result({"ports": ports, "context": ctx})

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError, AttributeError):
            loop.add_signal_handler(sig, stop.set)

    try:
        await stop.wait()
    except asyncio.CancelledError:
        pass
    finally:
        if dashboard is not None:
            dashboard.shutdown()
        await stop_all(servers)
        ctx.sink.record(
            event="listener_stopped",
            service="botpolice",
            severity="info",
            summary="decoy listeners stopped",
        )
        flush = getattr(ctx.sink.alerter, "flush", None)
        if callable(flush):
            with contextlib.suppress(Exception):
                await asyncio.to_thread(flush, 5.0)

    return {"ports": ports}
