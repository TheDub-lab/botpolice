"""Low-interaction decoy services.

Each module exposes ``start_<name>(ctx, host, port) -> asyncio.Server`` and a
handler. They are deliberately minimal: they never authenticate, never execute
input, cap every read, and time out every connection.
"""

from .common import ServiceContext, start_all, stop_all

__all__ = ["ServiceContext", "start_all", "stop_all"]
