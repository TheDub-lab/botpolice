"""Event sink: writes events to the hash-chained log and raises alerts.

Services call :meth:`EventSink.record` with only plain data. The sink caps the
raw payload, builds the log entry, appends it, and hands a normalized alert to
the alerter. Alerting is fire-and-forget and can never raise into the listener.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any

from .config import VALID_SEVERITIES, Limits
from .eventlog import EventLog, cap_payload

_SEVERITY_ORDER = {name: i for i, name in enumerate(VALID_SEVERITIES)}


class SourceTracker:
    """Per-source session totals attached to every alert for faster triage.

    Tracks, per source IP, when it was first and last seen, how many events it
    produced, the highest severity seen, and which services it touched. Bounded
    only by the number of distinct source IPs the listener has observed.
    """

    def __init__(self) -> None:
        self._sources: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def note(
        self, src_ip: str | None, service: str, severity: str, ts: str
    ) -> dict[str, Any] | None:
        if not src_ip:
            return None
        with self._lock:
            record = self._sources.get(src_ip)
            if record is None:
                record = {
                    "source_ip": src_ip,
                    "first_seen": ts,
                    "last_seen": ts,
                    "event_count": 0,
                    "highest_severity": "info",
                    "services": [],
                }
                self._sources[src_ip] = record
            record["last_seen"] = ts
            record["event_count"] += 1
            if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(
                record["highest_severity"], 0
            ):
                record["highest_severity"] = severity
            if service and service not in record["services"]:
                record["services"].append(service)
            return {**record, "services": list(record["services"])}


class NullAlerter:
    """No-op alerter used when alerting is disabled."""

    def notify(self, alert: dict[str, Any]) -> bool:
        return True

    def flush(self, timeout: float = 0.0) -> None:
        return None


class EventSink:
    def __init__(self, log: EventLog, alerter: Any | None = None, limits: Limits | None = None):
        self.log = log
        self.alerter = alerter or NullAlerter()
        self.limits = limits or Limits()
        self.sources = SourceTracker()

    def record(
        self,
        *,
        event: str,
        service: str,
        severity: str = "medium",
        src_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        placement: str | None = None,
        summary: str = "",
        raw: bytes | str = b"",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw_text, raw_len, truncated = cap_payload(raw, self.limits.payload_cap_bytes)
        fields: dict[str, Any] = {
            "event": event,
            "service": service,
            "severity": severity,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "placement": placement,
            "summary": summary,
            "raw": raw_text,
            "raw_len": raw_len,
            "truncated": truncated,
        }
        if extra:
            fields["extra"] = extra

        entry = self.log.append(fields)

        alert = {
            "severity": severity,
            "event": event,
            "service": service,
            "source_ip": src_ip,
            "placement": placement,
            "summary": summary,
            "timestamp": entry["ts"],
        }
        source = self.sources.note(src_ip, service, severity, entry["ts"])
        if source is not None:
            alert["source"] = source
        # Alerting must never break the listener: swallow delivery errors.
        with contextlib.suppress(Exception):
            self.alerter.notify(alert)
        return entry
