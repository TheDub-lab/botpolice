"""Shared test helpers."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from botpolice.eventlog import EventLog
from botpolice.sink import EventSink, NullAlerter


@dataclass
class TokenMatch:
    token: str
    placement: str


class MatchRecorder:
    """A stand-in canary matcher that records the text it was asked about."""

    def __init__(self, token: str = "canarytoken", placement: str = "lab") -> None:
        self.token = token
        self.placement = placement
        self.queries: list[str] = []

    def __call__(self, text: str):
        self.queries.append(text)
        if self.token in text:
            return TokenMatch(self.token, self.placement)
        return None


def make_sink(directory: Path) -> tuple[EventSink, EventLog]:
    log = EventLog(directory / "events.jsonl")
    sink = EventSink(log, alerter=NullAlerter())
    return sink, log


def make_tmpdir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory()


def server_port(server) -> int:
    return server.sockets[0].getsockname()[1]


async def read_all(reader, timeout: float = 5.0) -> bytes:
    """Read until EOF or timeout; never raises on close/timeout."""
    import asyncio

    buf = bytearray()
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)
