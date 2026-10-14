"""Off-box anchoring of the event log's chain head.

The log's SHA-256 chain makes tampering *detectable*, but a rewrite by someone
with write access to the log file would still produce a valid-looking chain. The
cheap fix is to ship the current chain head to somewhere the attacker does not
control (a webhook, or the operator's Telegram chat) on a schedule: a later
rewrite cannot reproduce a head that was already sent.

Anchoring reuses the alert transport and never raises into the listener; a dead
destination is silently ignored. Only a configured destination is contacted.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from .alerting import post_json
from .config import AlertConfig, AnchorConfig
from .eventlog import EventLog, utc_now


class ChainAnchor:
    """Periodically ships the log's chain head to a configured destination."""

    def __init__(
        self,
        config: AnchorConfig,
        alerts: AlertConfig,
        log: EventLog,
        deliver: bool = True,
    ) -> None:
        self.config = config
        self.alerts = alerts
        self.log = log
        self.deliver = deliver
        self.seq = 0

    @property
    def _telegram_enabled(self) -> bool:
        return bool(self.alerts.telegram_bot_token and self.alerts.telegram_chat_id)

    def _deliver(self, payload: dict[str, Any]) -> bool:
        """Send the anchor to every configured destination. Never raises."""
        if not self.deliver:
            return False
        delivered = False
        url = self.config.webhook_url or self.alerts.webhook_url
        if url:
            try:
                post_json(url, payload, self.config.timeout_seconds)
                delivered = True
            except Exception:
                pass
        if self.config.telegram and self._telegram_enabled:
            try:
                telegram = (
                    f"https://api.telegram.org/bot{self.alerts.telegram_bot_token}/sendMessage"
                )
                post_json(
                    telegram,
                    {"chat_id": self.alerts.telegram_chat_id, "text": format_anchor_text(payload)},
                    self.config.timeout_seconds,
                )
                delivered = True
            except Exception:
                pass
        return delivered

    def anchor_once(self) -> dict[str, Any] | None:
        """Anchor the current chain head. Returns the payload, or None if empty.

        The head is read, shipped, and then recorded as a local ``chain_anchor``
        event (so the anchored head is a genuine historical head — the recorded
        event is itself covered by the *next* anchor).
        """
        if not self.log.has_entries():
            return None
        head = self.log.head()
        self.seq += 1
        payload: dict[str, Any] = {
            "event": "chain_anchor",
            "head": head,
            "seq": self.seq,
            "ts": utc_now(),
            "log": str(self.log.path),
        }
        delivered = self._deliver(payload)
        self.log.append(
            {
                "event": "chain_anchor",
                "service": "botpolice",
                "severity": "info",
                "summary": f"chain anchor #{self.seq} {head[:12]}",
                "extra": {"head": head, "seq": self.seq, "delivered": delivered},
            }
        )
        payload["delivered"] = delivered
        return payload

    async def run(self) -> None:
        """Anchor on an interval until cancelled."""
        with contextlib.suppress(asyncio.CancelledError):
            while True:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(self.anchor_once)
                await asyncio.sleep(self.config.interval_seconds)


def format_anchor_text(payload: dict[str, Any]) -> str:
    return (
        "botpolice chain anchor\n"
        f"head: {payload.get('head', '-')}\n"
        f"seq: {payload.get('seq', '-')}\n"
        f"log: {payload.get('log', '-')}\n"
        f"time: {payload.get('ts', '-')}"
    )
