"""Append-only JSONL event log with a SHA-256 hash chain.

Every entry carries the SHA-256 hash of the canonical JSON of the previous
entry (``prev_hash``) and its own ``hash``. Editing, deleting, or reordering
any line breaks the chain, which ``verify`` reports as the first broken link.

The log treats all recorded payloads as untrusted bytes: they are truncated to
a hard cap and rendered with ``backslashreplace`` so nothing is interpreted.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def utc_now() -> str:
    """ISO-8601 UTC timestamp with microsecond precision."""
    return datetime.now(UTC).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(entry: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used for hashing (stable across runs)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def cap_payload(data: bytes | str, limit: int) -> tuple[str, int, bool]:
    """Return ``(text, original_len, truncated)`` for an untrusted payload.

    ``data`` is never decoded as anything but bytes; invalid sequences are
    escaped so the result is always JSON-safe plain text.
    """
    raw = data.encode("utf-8", "backslashreplace") if isinstance(data, str) else bytes(data)
    original_len = len(raw)
    truncated = original_len > limit
    chunk = raw[:limit] if truncated else raw
    text = chunk.decode("utf-8", errors="backslashreplace")
    return text, original_len, truncated


def compute_hash(entry_without_hash: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(entry_without_hash))


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_broken_line: int | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "first_broken_line": self.first_broken_line,
            "reason": self.reason,
        }


class EventLog:
    """Thread-safe append-only JSONL writer with a tamper-evident hash chain."""

    def __init__(self, path: str | Path, fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        if self.path.exists():
            self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        try:
            with self.path.open("rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                pos = max(0, size - 65536)
                fh.seek(pos)
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return GENESIS_HASH
        for line in reversed(tail.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return GENESIS_HASH
            return str(entry.get("hash", GENESIS_HASH))
        return GENESIS_HASH

    def append(self, fields: dict[str, Any]) -> dict[str, Any]:
        """Append one entry and return the stored record (including hashes)."""
        with self._lock:
            entry: dict[str, Any] = {"ts": utc_now()}
            entry.update(fields)
            entry.pop("hash", None)
            entry["prev_hash"] = self._last_hash
            entry["hash"] = compute_hash(entry)

            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                if self.fsync:
                    import os

                    os.fsync(fh.fileno())
            self._last_hash = entry["hash"]
            return entry

    def read_all(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def verify_log(path: str | Path) -> VerifyResult:
    """Walk the hash chain and report the first broken link, if any."""
    p = Path(path)
    if not p.exists():
        return VerifyResult(ok=True, entries=0)

    with p.open("r", encoding="utf-8") as fh:
        content = fh.read()

    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # trailing newline

    prev_hash = GENESIS_HASH
    count = 0
    for index, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            return VerifyResult(False, count, index, "empty line in the middle of the log")
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return VerifyResult(False, count, index, f"invalid JSON: {exc}")
        if not isinstance(entry, dict):
            return VerifyResult(False, count, index, "entry is not a JSON object")

        stored_hash = entry.pop("hash", None)
        if stored_hash is None:
            return VerifyResult(False, count, index, "missing 'hash' field")
        if entry.get("prev_hash") != prev_hash:
            return VerifyResult(
                False,
                count,
                index,
                f"prev_hash mismatch (expected {prev_hash}, found {entry.get('prev_hash')})",
            )
        if compute_hash(entry) != stored_hash:
            return VerifyResult(False, count, index, "hash mismatch (entry was modified)")

        prev_hash = stored_hash
        count += 1

    return VerifyResult(ok=True, entries=count)
