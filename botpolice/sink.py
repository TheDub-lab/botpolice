"""Event sink: writes events to the hash-chained log and raises alerts.

Services call :meth:`EventSink.record` with only plain data. The sink caps the
raw payload, builds the log entry, appends it, and hands a normalized alert to
the alerter. Alerting is fire-and-forget and can never raise into the listener.
"""

from __future__ import annotations

import contextlib
from typing import Any

from .config import Limits
from .eventlog import EventLog, cap_payload


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
        # Alerting must never break the listener: swallow delivery errors.
        with contextlib.suppress(Exception):
            self.alerter.notify(alert)
        return entry
