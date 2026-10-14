"""Alert dispatch: generic JSON webhook and Telegram, with dedupe + rate limit.

Delivery happens on a background thread and swallows every error: a dead or
misconfigured webhook can never block or crash the listener. Only the
configured alert destination is ever contacted (no other outbound traffic).
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
import urllib.request
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .config import VALID_SEVERITIES, AlertConfig

_SEVERITY_RANK = {name: i for i, name in enumerate(VALID_SEVERITIES)}


def severity_at_least(severity: str, minimum: str) -> bool:
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(minimum, 0)


class Alerter:
    """Filters, deduplicates, rate-limits, and delivers alerts."""

    def __init__(self, config: AlertConfig, deliver: bool = True) -> None:
        self.config = config
        self.deliver = deliver
        self.sent: list[dict[str, Any]] = []
        self.suppressed = 0
        self.rejected = 0
        self._lock = threading.Lock()
        self._last_seen: dict[tuple[str, str, str], float] = {}
        self._ip_times: dict[str, deque[float]] = defaultdict(deque)
        self._executor: ThreadPoolExecutor | None = None
        if deliver and (config.webhook_url or self._telegram_enabled):
            self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="botpolice-alert")

    @property
    def _telegram_enabled(self) -> bool:
        return bool(self.config.telegram_bot_token and self.config.telegram_chat_id)

    def notify(self, alert: dict[str, Any]) -> bool:
        """Return True if the alert was accepted for delivery, else False."""
        severity = str(alert.get("severity", "info"))
        if not severity_at_least(severity, self.config.min_severity):
            self.rejected += 1
            return False

        source_ip = str(alert.get("source_ip") or "-")
        event = str(alert.get("event", "event"))
        now = time.monotonic()

        with self._lock:
            key = (source_ip, event, severity)
            last = self._last_seen.get(key)
            if last is not None and (now - last) < self.config.dedupe_window_seconds:
                self.suppressed += 1
                return False

            times = self._ip_times[source_ip]
            cutoff = now - self.config.dedupe_window_seconds
            while times and times[0] < cutoff:
                times.popleft()
            if len(times) >= self.config.per_ip_max_per_window:
                self.suppressed += 1
                return False

            self._last_seen[key] = now
            times.append(now)
            self._last_seen = {
                k: v
                for k, v in self._last_seen.items()
                if (now - v) < self.config.dedupe_window_seconds
            }

        self.sent.append(alert)
        if self._executor is not None:
            with contextlib.suppress(RuntimeError):
                self._executor.submit(self._deliver, alert)
        return True

    def _deliver(self, alert: dict[str, Any]) -> None:
        try:
            if self.config.webhook_url:
                _post_json(self.config.webhook_url, alert, self.config.timeout_seconds)
        except Exception:
            pass
        try:
            if self._telegram_enabled:
                self._send_telegram(alert)
        except Exception:
            pass

    def _send_telegram(self, alert: dict[str, Any]) -> None:
        text = format_alert_text(alert)
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        payload = {"chat_id": self.config.telegram_chat_id, "text": text}
        _post_json(url, payload, self.config.timeout_seconds)

    def flush(self, timeout: float = 5.0) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None


def format_alert_text(alert: dict[str, Any]) -> str:
    lines = [
        f"[{str(alert.get('severity', 'info')).upper()}] {alert.get('event', 'event')}",
        f"service: {alert.get('service', '-')}  source: {alert.get('source_ip', '-')}",
        f"{alert.get('summary', '')}".rstrip(),
    ]
    if alert.get("placement"):
        lines.append(f"placement: {alert['placement']}")
    if alert.get("timestamp"):
        lines.append(f"at {alert['timestamp']}")
    return "\n".join(lines)


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "botpolice/0.1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        response.read()


def build_alerter(config: AlertConfig, deliver: bool = True) -> Alerter:
    return Alerter(config, deliver=deliver)
