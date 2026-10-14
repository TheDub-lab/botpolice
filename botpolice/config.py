"""Configuration loading and validation.

Config is a JSON document loaded with ``botpolice --config path``. Missing
values fall back to safe defaults (loopback bind, high ports, conservative
read caps). Unknown keys are ignored so configs survive upgrades.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BIND = "127.0.0.1"

# Well-known decoy defaults, all above 1024 and none colliding with a default
# install of the real services (SSH 22, HTTP 80, PostgreSQL 5432 is avoided).
DEFAULT_PORTS = {
    "ssh": 2222,
    "http": 8080,
    "compute": 11435,
    "database": 15432,
    "adb": 5555,
}

VALID_SEVERITIES = ("info", "medium", "high")

# Generic off-brand Android TV box identity. Deliberately vague and fake: it
# imitates the class of cheap device the Kimwolf botnet targeted, without
# copying any real product. Override per deployment to vary the decoy.
DEFAULT_ADB_IDENTITY = {
    "ro.product.name": "tvbox",
    "ro.product.model": "TV Box",
    "ro.product.device": "tvbox",
    "ro.product.brand": "Generic",
    "ro.build.version.release": "11",
    "features": "cmd,shell_v2,shell_v3",
}


@dataclass
class Limits:
    max_connections: int = 64
    per_connection_timeout_seconds: float = 10.0
    max_read_bytes: int = 4096
    payload_cap_bytes: int = 4096
    max_header_bytes: int = 16384

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Limits:
        data = data or {}
        return cls(
            max_connections=int(data.get("max_connections", 64)),
            per_connection_timeout_seconds=float(
                data.get("per_connection_timeout_seconds", 10.0)
            ),
            max_read_bytes=int(data.get("max_read_bytes", 4096)),
            payload_cap_bytes=int(data.get("payload_cap_bytes", 4096)),
            max_header_bytes=int(data.get("max_header_bytes", 16384)),
        )


@dataclass
class ServiceConfig:
    enabled: bool = True
    port: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, default_port: int) -> ServiceConfig:
        data = data or {}
        return cls(enabled=bool(data.get("enabled", True)), port=int(data.get("port", default_port)))


@dataclass
class AdbConfig:
    """Runtime options for the fake Android TV box (ADB) decoy.

    All values are conservative: a small message cap, a short command budget per
    session, and an idle timeout so a hung or flooding peer cannot pin resources.
    The identity strings and canned replies are inert data — they are only ever
    sent or logged, never interpreted.
    """

    bind: str | None = None
    identity: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_ADB_IDENTITY))
    responses_file: str = "adb_responses.example.json"
    max_message_bytes: int = 65536
    max_commands_per_session: int = 64
    max_total_bytes_per_session: int = 4 * 1024 * 1024
    idle_timeout_seconds: float = 30.0
    faster_than_human_gap_ms: float = 150.0
    min_commands_for_automation: int = 3

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AdbConfig:
        data = data or {}
        identity = data.get("identity")
        if not isinstance(identity, dict) or not identity:
            identity = dict(DEFAULT_ADB_IDENTITY)
        else:
            identity = {str(k): str(v) for k, v in identity.items()}
        return cls(
            bind=data.get("bind"),
            identity=identity,
            responses_file=str(data.get("responses_file", "adb_responses.example.json")),
            max_message_bytes=max(1024, int(data.get("max_message_bytes", 65536))),
            max_commands_per_session=max(1, int(data.get("max_commands_per_session", 64))),
            max_total_bytes_per_session=max(
                1024, int(data.get("max_total_bytes_per_session", 4 * 1024 * 1024))
            ),
            idle_timeout_seconds=max(1.0, float(data.get("idle_timeout_seconds", 30.0))),
            faster_than_human_gap_ms=max(0.0, float(data.get("faster_than_human_gap_ms", 150.0))),
            min_commands_for_automation=max(1, int(data.get("min_commands_for_automation", 3))),
        )


@dataclass
class AlertConfig:
    webhook_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: str = "medium"
    dedupe_window_seconds: float = 120.0
    per_ip_max_per_window: int = 5
    timeout_seconds: float = 5.0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AlertConfig:
        data = data or {}
        telegram = data.get("telegram") or {}
        min_severity = str(data.get("min_severity", "medium")).lower()
        if min_severity not in VALID_SEVERITIES:
            min_severity = "medium"
        return cls(
            webhook_url=data.get("webhook_url"),
            telegram_bot_token=telegram.get("bot_token"),
            telegram_chat_id=telegram.get("chat_id"),
            min_severity=min_severity,
            dedupe_window_seconds=float(data.get("dedupe_window_seconds", 120.0)),
            per_ip_max_per_window=int(data.get("per_ip_max_per_window", 5)),
            timeout_seconds=float(data.get("timeout_seconds", 5.0)),
        )


@dataclass
class DashboardConfig:
    enabled: bool = False
    port: int = 8090

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> DashboardConfig:
        data = data or {}
        return cls(enabled=bool(data.get("enabled", False)), port=int(data.get("port", 8090)))


@dataclass
class Config:
    bind: str = DEFAULT_BIND
    log_path: str = "events.jsonl"
    canary_store: str = "canaries.json"
    canary_output_dir: str = "canaries"
    services: dict[str, ServiceConfig] = field(default_factory=dict)
    adb: AdbConfig = field(default_factory=AdbConfig)
    limits: Limits = field(default_factory=Limits)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    advertise_url: str | None = None
    source: Path | None = None

    def resolve(self, path_str: str) -> Path:
        """Resolve ``path_str`` relative to the config file's directory."""
        return self.resolved(path_str, self.source)

    def listener_url(self) -> str:
        """Address embedded in generated decoys (override with advertise_url)."""
        if self.advertise_url:
            return self.advertise_url.rstrip("/")
        return f"http://{self.bind}:{self.services['http'].port}"

    def apply_env(self, environ: Mapping[str, str] | None = None) -> Config:
        """Apply a small set of ``BOTPOLICE_*`` environment overrides in place.

        Useful for containers, where the bind address differs from the host
        config (e.g. ``BOTPOLICE_BIND=0.0.0.0``) without editing the file.
        """
        env = environ if environ is not None else os.environ
        if env.get("BOTPOLICE_BIND"):
            self.bind = env["BOTPOLICE_BIND"]
        if env.get("BOTPOLICE_ADVERTISE_URL"):
            self.advertise_url = env["BOTPOLICE_ADVERTISE_URL"]
        if env.get("BOTPOLICE_LOG_PATH"):
            self.log_path = env["BOTPOLICE_LOG_PATH"]
        if env.get("BOTPOLICE_CANARY_STORE"):
            self.canary_store = env["BOTPOLICE_CANARY_STORE"]
        if env.get("BOTPOLICE_CANARY_OUTPUT_DIR"):
            self.canary_output_dir = env["BOTPOLICE_CANARY_OUTPUT_DIR"]
        if env.get("BOTPOLICE_WEBHOOK_URL"):
            self.alerts.webhook_url = env["BOTPOLICE_WEBHOOK_URL"]
        return self

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Config:
        data = data or {}
        raw_services = data.get("services") or {}
        services = {
            name: ServiceConfig.from_dict(raw_services.get(name), default_port)
            for name, default_port in DEFAULT_PORTS.items()
        }
        return cls(
            bind=str(data.get("bind", DEFAULT_BIND)),
            log_path=str(data.get("log_path", "events.jsonl")),
            canary_store=str(data.get("canary_store", "canaries.json")),
            canary_output_dir=str(data.get("canary_output_dir", "canaries")),
            services=services,
            adb=AdbConfig.from_dict(data.get("adb")),
            limits=Limits.from_dict(data.get("limits")),
            alerts=AlertConfig.from_dict(data.get("alerts")),
            dashboard=DashboardConfig.from_dict(data.get("dashboard")),
            advertise_url=data.get("advertise_url"),
        )

    def base_dir(self, source: Path | None) -> Path:
        """Directory used to resolve relative paths (the config file's dir)."""
        if source is None:
            return Path.cwd()
        return source.resolve().parent

    def resolved(self, path_str: str, source: Path | None) -> Path:
        p = Path(path_str)
        if p.is_absolute():
            return p
        return self.base_dir(source) / p


def load_config(path: str | Path) -> Config:
    """Load config from ``path``.

    Returns ``(config, source_path)`` semantics via :func:`load_config_with_source`
    when relative paths need resolving; this helper just returns the config.
    """
    config, _ = load_config_with_source(path)
    return config


def load_config_with_source(path: str | Path) -> tuple[Config, Path]:
    source = Path(path)
    with source.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config root must be a JSON object")
    config = Config.from_dict(data)
    config.source = source
    config.apply_env()
    return config, source
