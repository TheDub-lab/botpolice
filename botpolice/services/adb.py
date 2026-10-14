"""Fake Android TV box with an "open" ADB port (TCP 5555 decoy).

Kimwolf-style botnets scan for Android devices that expose ADB without
authentication, then use ``adb shell`` to download and run a payload. This
decoy speaks just enough of the ADB wire protocol to hold that conversation,
log every command and pushed file, and refuse to be useful:

* It accepts the handshake and AUTH with **no credentials** (that is the bait).
* ``shell:`` streams return canned output from a data file; unknown commands get
  a shell-style "not found".
* ``sync:`` file transfers are accepted, streamed through SHA-256, and
  **discarded**. Nothing is ever written to disk, executed, or evaluated.
* Every other service (``tcp:``, ``jdwp:``, ``reverse:``, ``install:`` ...) is
  refused and logged.

The protocol parser (:func:`parse_header` / :func:`build_message`) is pure and
unit-testable; the connection loop only ever reads, hashes, and replies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import DEFAULT_ADB_IDENTITY, AdbConfig
from .common import ServiceContext, peer
from .httpio import local_port

ADB_HEADER_SIZE = 24
ADB_VERSION = 0x01000000
ADB_MAXDATA = 256 * 1024

# Real ADB commands. Anything else is treated as a malformed message.
ADB_COMMANDS = frozenset({b"CNXN", b"AUTH", b"OPEN", b"OKAY", b"CLSE", b"WRTE", b"SYNC", b"STLS"})

# Bytes of a sync request that we are ever willing to buffer before giving up.
_MAX_SYNC_BUFFER = 128 * 1024

DEFAULT_IDENTITY: dict[str, str] = dict(DEFAULT_ADB_IDENTITY)

# Canned, inert outputs. Used only when no responses file is present so the
# container always has something to say. All values are fake.
DEFAULT_RESPONSES: dict[str, str] = {
    "id": "uid=2000(shell) gid=2000(shell) context=u:r:shell:s0",
    "whoami": "shell",
    "uname -a": "Linux localhost 5.10.66 #1 SMP PREEMPT aarch64 Toybox",
    "uname": "Linux",
    "getprop": (
        "[ro.product.model]: [TV Box]\n"
        "[ro.product.name]: [tvbox]\n"
        "[ro.build.version.release]: [11]\n"
        "[ro.build.type]: [user]\n"
        "[ro.debuggable]: [1]\n"
    ),
    "ls": "acct\ncache\nconfig\ndata\ndev\netc\nmnt\nproc\nsbin\nsdcard\nstorage\nsys\nsystem\nvendor\n",
    "ls -la /data/local/tmp": (
        "total 0\n"
        "drwxrwxrwx 2 shell shell 4096 2026-01-01 00:00 .\n"
        "drwx--x--x 4 shell shell 4096 2026-01-01 00:00 ..\n"
    ),
    "cat /proc/cpuinfo": "Processor\t: AArch64 Processor rev 4 (aarch64)\nHardware\t: Amlogic\n",
    "cat /proc/version": "Linux version 5.10.66 (build@localhost) aarch64-linux-android #1 SMP PREEMPT\n",
    "pm list packages": (
        "package:com.android.settings\n"
        "package:com.android.systemui\n"
        "package:com.android.providers.settings\n"
    ),
    "ps": "USER   PID  PPID VSZ   RSS WCHAN ADDR S NAME\nshell  123  1  12345 2345 0 0 S sh\n",
    "ps -A": "USER   PID  PPID VSZ   RSS WCHAN ADDR S NAME\nshell  123  1  12345 2345 0 0 S sh\n",
    "netstat": "Active Internet connections\n",
}


class AdbProtocolError(Exception):
    """Raised when a 24-byte ADB header cannot be trusted."""


@dataclass(frozen=True)
class AdbHeader:
    command: bytes
    arg0: int
    arg1: int
    data_length: int
    data_checksum: int
    magic: int

    @property
    def name(self) -> str:
        return self.command.decode("ascii", "replace")


def _command_int(command: bytes) -> int:
    return int.from_bytes(command, "little")


def parse_header(buf: bytes, max_data_length: int | None = None) -> AdbHeader:
    """Parse and validate a 24-byte ADB message header.

    Raises :class:`AdbProtocolError` for a short buffer, unknown command, bad
    magic, or a payload larger than the cap. ``magic`` must equal the command
    integer XOR ``0xFFFFFFFF``.
    """
    if len(buf) < ADB_HEADER_SIZE:
        raise AdbProtocolError("short header")
    command, arg0, arg1, data_length, data_checksum, magic = struct.unpack(
        "<4sIIIII", buf[:ADB_HEADER_SIZE]
    )
    if command not in ADB_COMMANDS:
        raise AdbProtocolError(f"unknown command {command!r}")
    if magic != (_command_int(command) ^ 0xFFFFFFFF):
        raise AdbProtocolError("bad magic")
    limit = ADB_MAXDATA if max_data_length is None else min(max_data_length, ADB_MAXDATA)
    if data_length > limit:
        raise AdbProtocolError(f"data_length {data_length} exceeds cap {limit}")
    return AdbHeader(command, arg0, arg1, data_length, data_checksum, magic)


def build_message(command: bytes, arg0: int = 0, arg1: int = 0, data: bytes = b"") -> bytes:
    """Encode one ADB message (header + payload)."""
    if len(command) != 4:
        raise ValueError("command must be exactly 4 bytes")
    data = bytes(data)
    checksum = sum(data) & 0xFFFFFFFF
    magic = _command_int(command) ^ 0xFFFFFFFF
    header = struct.pack(
        "<4sIIIII", command, arg0 & 0xFFFFFFFF, arg1 & 0xFFFFFFFF, len(data), checksum, magic
    )
    return header + data


def tag_shell_command(command: str) -> list[str]:
    """Heuristically tag a shell command for triage. Never executes anything."""
    c = command.lower()
    tags: set[str] = set()
    if any(t in c for t in ("curl", "wget", "tftp", "http://", "https://", "ftp://")):
        tags.add("download")
    if "chmod" in c:
        tags.add("chmod")
    if "/data/local/tmp" in c:
        tags.add("tmp_exec")
    if "pm install" in c or (".apk" in c and "install" in c):
        tags.add("pm_install")
    if ".apk" in c:
        tags.add("apk")
    if any(
        t in c
        for t in ("ollama", "llama", "gguf", "safetensors", ".onnx", "/models", ":11434", "weights")
    ):
        tags.add("ai_model")
    if "base64" in c:
        tags.add("obfuscation")
    if any(t in c for t in ("crontab", "/etc/init", "init.d", "boot")):
        tags.add("persistence")
    return sorted(tags)


class AdbData:
    """Canned replies + fake device identity, optionally loaded from a file."""

    def __init__(self, responses: dict[str, str], identity: dict[str, str]) -> None:
        self.responses = responses
        self.identity = identity

    @classmethod
    def default(cls, identity: dict[str, str] | None = None) -> AdbData:
        return cls(dict(DEFAULT_RESPONSES), dict(identity or DEFAULT_IDENTITY))

    @classmethod
    def load(cls, path: str | Path, identity: dict[str, str] | None = None) -> AdbData:
        """Load ``{"identity": {...}, "responses": {...}}``; fall back safely."""
        base_identity = dict(identity or DEFAULT_IDENTITY)
        try:
            with Path(path).open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return cls.default(base_identity)
        if not isinstance(doc, dict):
            return cls.default(base_identity)

        responses = dict(DEFAULT_RESPONSES)
        file_identity = base_identity
        raw_responses = doc.get("responses")
        raw_identity = doc.get("identity")
        if isinstance(raw_responses, dict):
            responses.update({str(k): str(v) for k, v in raw_responses.items()})
        else:
            # Tolerate a flat "command": "output" map.
            responses.update(
                {str(k): str(v) for k, v in doc.items() if isinstance(v, str)}
            )
        if isinstance(raw_identity, dict) and raw_identity:
            file_identity = {str(k): str(v) for k, v in raw_identity.items()}
        return cls(responses, file_identity)

    def lookup(self, command: str) -> str | None:
        key = command.strip()
        if not key:
            return None
        if key in self.responses:
            return self.responses[key]
        first = key.split()[0]
        return self.responses.get(first)

    def banner(self) -> bytes:
        device = self.identity.get("ro.product.device", "tvbox")
        props = ";".join(f"{k}={v}" for k, v in self.identity.items())
        return f"{device}::{props}\0".encode("utf-8", "replace")


@dataclass
class _SyncState:
    pending: dict[str, Any] | None = None
    buffer: bytearray = field(default_factory=bytearray)


@dataclass
class _Stream:
    device_id: int
    client_id: int
    kind: str
    sync: _SyncState | None = None


class _Session:
    """Per-connection timing and counters used for triage and the summary."""

    def __init__(self, gap_threshold_ms: float, min_commands: int) -> None:
        self.start = time.monotonic()
        self.commands = 0
        self.total_bytes = 0
        self.tags: set[str] = set()
        self.gaps_ms: list[float] = []
        self.high = 0
        self._last_command: float | None = None
        self.gap_threshold_ms = gap_threshold_ms
        self.min_commands = min_commands

    def note_command(self, tags: list[str] | None = None) -> None:
        now = time.monotonic()
        if self._last_command is not None:
            self.gaps_ms.append((now - self._last_command) * 1000.0)
            if len(self.gaps_ms) > 64:
                del self.gaps_ms[:-64]
        self._last_command = now
        self.commands += 1
        if tags:
            self.tags.update(tags)

    def note_bytes(self, count: int) -> None:
        self.total_bytes += max(0, count)

    @property
    def automated(self) -> bool:
        if self.commands < self.min_commands:
            return False
        if not self.gaps_ms:
            return True
        return (sum(self.gaps_ms) / len(self.gaps_ms)) <= self.gap_threshold_ms

    def extra(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "commands": self.commands,
            "total_bytes": self.total_bytes,
            "duration_ms": round((time.monotonic() - self.start) * 1000.0, 1),
            "automated": self.automated,
        }
        if self.gaps_ms:
            info["avg_gap_ms"] = round(sum(self.gaps_ms) / len(self.gaps_ms), 1)
        if self.tags:
            info["tags"] = sorted(self.tags)
        return info


async def _read_exactly(
    reader: asyncio.StreamReader, count: int, timeout: float
) -> bytes | None:
    """Read exactly ``count`` bytes; return ``None`` on timeout, EOF, or error."""
    if count <= 0:
        return b""
    try:
        return await asyncio.wait_for(reader.readexactly(count), timeout=timeout)
    except (asyncio.IncompleteReadError, TimeoutError, OSError):
        return None


class _Connection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ctx: ServiceContext,
        config: AdbConfig,
        data: AdbData,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.ctx = ctx
        self.config = config
        self.data = data
        self.src_ip, self.src_port = peer(writer.get_extra_info("peername"))
        self.dst_port = local_port(writer)
        self.session = _Session(
            config.faster_than_human_gap_ms, config.min_commands_for_automation
        )
        self.streams: dict[int, _Stream] = {}
        self.next_id = 1
        self.limit_hit = False

    def _record(
        self,
        event: str,
        severity: str,
        summary: str,
        raw: bytes | str = b"",
        extra: dict[str, Any] | None = None,
        placement: str | None = None,
    ) -> None:
        if severity == "high":
            self.session.high += 1
        self.ctx.sink.record(
            event=event,
            service="adb",
            severity=severity,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            placement=placement,
            summary=summary,
            raw=raw,
            extra=extra,
        )

    async def _send(self, command: bytes, arg0: int = 0, arg1: int = 0, data: bytes = b"") -> None:
        try:
            self.writer.write(build_message(command, arg0, arg1, data))
            await self.writer.drain()
        except (ConnectionError, OSError):
            pass

    def _alloc_id(self) -> int:
        stream_id = self.next_id
        self.next_id += 1
        return stream_id

    async def run(self) -> None:
        self._record(
            "adb_connection",
            "medium",
            f"adb client connected from {self.src_ip}",
            extra={"protocol": "adb"},
        )
        try:
            while not self.limit_hit:
                message = await self._read_message()
                if message is None:
                    break
                header, payload = message
                if self.session.total_bytes > self.config.max_total_bytes_per_session:
                    self._record(
                        "adb_session_limit",
                        "high",
                        "adb session byte cap exceeded",
                        extra=self.session.extra(),
                    )
                    self.limit_hit = True
                    break
                await self._dispatch(header, payload)
                if self.session.commands > self.config.max_commands_per_session:
                    self._record(
                        "adb_session_limit",
                        "high",
                        "adb session command cap exceeded",
                        extra=self.session.extra(),
                    )
                    self.limit_hit = True
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            if self.session.commands > 0 or self.limit_hit:
                severity = "high" if self.session.high > 0 else "medium"
                self._record(
                    "adb_session_summary",
                    severity,
                    f"adb session ended: {self.session.commands} command(s)",
                    extra=self.session.extra(),
                )
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _read_message(self) -> tuple[AdbHeader, bytes] | None:
        header_bytes = await _read_exactly(
            self.reader, ADB_HEADER_SIZE, self.config.idle_timeout_seconds
        )
        if header_bytes is None:
            return None
        try:
            header = parse_header(header_bytes, self.config.max_message_bytes)
        except AdbProtocolError as exc:
            self._record(
                "adb_malformed",
                "medium",
                f"malformed adb header: {exc}",
                raw=header_bytes,
                extra={"reason": str(exc)},
            )
            return None

        payload = b""
        if header.data_length:
            payload = await _read_exactly(
                self.reader, header.data_length, self.config.idle_timeout_seconds
            )
            if payload is None:
                self._record(
                    "adb_malformed", "medium", "truncated adb payload", raw=header_bytes
                )
                return None
        self.session.note_bytes(header.data_length)
        return header, payload

    async def _dispatch(self, header: AdbHeader, payload: bytes) -> None:
        name = header.name
        if name == "CNXN":
            self._record(
                "adb_handshake",
                "medium",
                "adb CNXN handshake",
                raw=payload,
                extra={"version": hex(header.arg0), "maxdata": header.arg1},
            )
            await self._send(b"CNXN", ADB_VERSION, ADB_MAXDATA, self.data.banner())
        elif name == "AUTH":
            self._record(
                "adb_handshake",
                "medium",
                "adb AUTH accepted without credentials",
                raw=payload,
                extra={"auth_type": header.arg0},
            )
            await self._send(b"OKAY", 0, 0)
        elif name == "OPEN":
            await self._handle_open(header, payload)
        elif name == "WRTE":
            await self._handle_write(header, payload)
        elif name == "CLSE":
            self._close_stream(header)
        elif name == "STLS":
            await self._send(b"OKAY", 0, 0)

    def _close_stream(self, header: AdbHeader) -> None:
        stream = self.streams.pop(header.arg1, None) or self.streams.pop(header.arg0, None)
        if stream is not None and stream.sync is not None and stream.sync.pending is not None:
            pending = stream.sync.pending
            self._finalize_push(pending, closed_early=True)
            stream.sync.pending = None

    async def _handle_open(self, header: AdbHeader, payload: bytes) -> None:
        dest = payload.split(b"\0", 1)[0].decode("utf-8", "replace")
        client_id = header.arg0
        if dest == "shell" or dest.startswith("shell:"):
            device_id = self._alloc_id()
            self.streams[device_id] = _Stream(device_id, client_id, "shell")
            await self._send(b"OKAY", device_id, client_id)
            command = dest[len("shell:") :].strip() if dest.startswith("shell:") else ""
            if command:
                await self._run_shell(device_id, client_id, command)
            else:
                self._record(
                    "adb_shell_open", "medium", f"interactive adb shell opened from {self.src_ip}"
                )
            return
        if dest == "sync" or dest.startswith("sync:"):
            device_id = self._alloc_id()
            self.streams[device_id] = _Stream(device_id, client_id, "sync", _SyncState())
            await self._send(b"OKAY", device_id, client_id)
            self._record(
                "adb_sync_open", "medium", f"adb sync (file transfer) opened from {self.src_ip}"
            )
            return
        service = dest.split(":", 1)[0] if dest else "unknown"
        self._record(
            "adb_open_refused",
            "medium",
            f"refused adb service: {service}",
            raw=payload,
            extra={"service": service},
        )
        await self._send(b"CLSE", header.arg0, client_id)

    async def _run_shell(self, device_id: int, client_id: int, command: str) -> None:
        tags = tag_shell_command(command)
        self.session.note_command(tags)
        placement = None
        if self.ctx.matcher is not None:
            match = self.ctx.matcher(command)
            if match is not None:
                placement = match.placement
        output = self.data.lookup(command)
        if output is None:
            output = f"sh: {command.split()[0]}: not found"
        if not output.endswith("\n"):
            output += "\n"
        self._record(
            "adb_shell_command",
            "high",
            f"adb shell command: {command}",
            raw=command,
            extra={"command": command, "tags": tags},
            placement=placement,
        )
        await self._send(b"WRTE", device_id, client_id, output.encode("utf-8", "replace"))
        await self._send(b"CLSE", device_id, client_id)
        self.streams.pop(device_id, None)

    async def _handle_write(self, header: AdbHeader, payload: bytes) -> None:
        stream = self.streams.get(header.arg1) or self.streams.get(header.arg0)
        if stream is None:
            self._record(
                "adb_write_unknown",
                "medium",
                "adb WRTE for unknown stream",
                raw=payload,
            )
            return
        if stream.kind == "shell":
            if payload:
                self._record(
                    "adb_shell_input",
                    "medium",
                    "stdin to adb shell",
                    raw=payload,
                    extra={"stream": stream.device_id},
                )
            return
        if stream.kind == "sync" and stream.sync is not None:
            await self._feed_sync(stream, payload)

    async def _sync_reply(self, stream: _Stream, tag: bytes, data: bytes = b"") -> None:
        body = tag + struct.pack("<I", len(data)) + data
        await self._send(b"WRTE", stream.device_id, stream.client_id, body)

    async def _feed_sync(self, stream: _Stream, payload: bytes) -> None:
        state = stream.sync
        assert state is not None
        state.buffer.extend(payload)
        buf = state.buffer
        if len(buf) > _MAX_SYNC_BUFFER:
            self._record(
                "adb_malformed", "medium", "adb sync buffer overflow, dropping stream"
            )
            buf.clear()
            return
        while True:
            if len(buf) < 4:
                return
            tag = bytes(buf[:4])
            if tag == b"SEND":
                if len(buf) < 12:
                    return
                mode = int.from_bytes(buf[4:8], "little")
                size = int.from_bytes(buf[8:12], "little")
                end = buf.find(b"\0", 12)
                if end == -1:
                    return
                name = bytes(buf[12:end]).decode("utf-8", "replace")
                consumed = end + 1
                pad = (-consumed) % 4
                if len(buf) < consumed + pad:
                    return
                del buf[: consumed + pad]
                state.pending = {
                    "name": name,
                    "mode": mode,
                    "size": size,
                    "received": 0,
                    "truncated": False,
                    "hasher": hashlib.sha256(),
                }
                await self._sync_reply(stream, b"OKAY")
            elif tag == b"DATA":
                if len(buf) < 8:
                    return
                size = int.from_bytes(buf[4:8], "little")
                if len(buf) < 8 + size:
                    return
                chunk = bytes(buf[8 : 8 + size])
                del buf[: 8 + size]
                pending = state.pending
                if pending is not None:
                    remaining = max(0, pending["size"] - pending["received"])
                    take = chunk[:remaining]
                    if not pending["truncated"]:
                        pending["hasher"].update(take)
                        pending["received"] += len(take)
                        if len(take) < len(chunk):
                            pending["truncated"] = True
                await self._sync_reply(stream, b"OKAY")
            elif tag == b"DONE":
                if len(buf) < 8:
                    return
                del buf[:8]
                if state.pending is not None:
                    self._finalize_push(state.pending)
                    state.pending = None
                await self._sync_reply(stream, b"OKAY")
            elif tag == b"RECV":
                path, consumed, pad = self._sync_path(buf, 4)
                if path is None:
                    return
                del buf[: consumed + pad]
                self.session.note_command([])
                self._record(
                    "adb_file_pull",
                    "high",
                    f"adb file pull requested: {path}",
                    raw=path,
                    extra={"filename": path},
                )
                await self._sync_reply(stream, b"FAIL", b"no such file")
            elif tag in (b"STAT", b"LIST"):
                if len(buf) < 8:
                    return
                end = buf.find(b"\0", 4)
                if end == -1:
                    return
                consumed = end + 1
                pad = (-consumed) % 4
                if len(buf) < consumed + pad:
                    return
                del buf[: consumed + pad]
                await self._sync_reply(stream, b"FAIL", b"no such file")
            elif tag == b"QUIT":
                del buf[:4]
                return
            elif tag in (b"OKAY", b"FAIL"):
                if len(buf) < 8:
                    return
                size = int.from_bytes(buf[4:8], "little")
                if len(buf) < 8 + size:
                    return
                del buf[: 8 + size]
            else:
                del buf[:1]

    @staticmethod
    def _sync_path(buf: bytearray, start: int) -> tuple[str | None, int, int]:
        end = buf.find(b"\0", start)
        if end == -1:
            return None, 0, 0
        path = bytes(buf[start:end]).decode("utf-8", "replace")
        consumed = end + 1
        pad = (-consumed) % 4
        return path, consumed, pad

    def _finalize_push(self, pending: dict[str, Any], closed_early: bool = False) -> None:
        self.session.note_command([])
        digest = pending["hasher"].hexdigest()
        size = pending["received"]
        self._record(
            "adb_file_push",
            "high",
            f"adb file push: {pending['name']} ({size} bytes)",
            raw=pending["name"],
            extra={
                "filename": pending["name"],
                "declared_size": pending["size"],
                "received_size": size,
                "sha256": digest,
                "mode": pending["mode"],
                "truncated": pending["truncated"] or size < pending["size"],
                "closed_early": closed_early,
                "stored": False,
                "note": "content hashed and discarded; never written or executed",
            },
        )


async def start_adb(
    ctx: ServiceContext,
    host: str,
    port: int,
    config: AdbConfig | None = None,
    data: AdbData | None = None,
) -> asyncio.AbstractServer:
    cfg = config or AdbConfig()
    adb_data = data or AdbData.default(cfg.identity)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with ctx.limiter:
            await _Connection(reader, writer, ctx, cfg, adb_data).run()

    return await asyncio.start_server(handler, host, port, limit=65536)
