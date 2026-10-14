"""Command-line interface for botpolice.

    botpolice run --config config.json
    botpolice canary new --placement <name> --type env|aws|ssh|json|tripwire|markdown|agents|claude
    botpolice canary list [--store canaries.json]
    botpolice verify-log --path events.jsonl
    botpolice rotate-decoys [--config config.json]
    botpolice anchor [--config config.json]
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path

from . import __version__
from .canary import VALID_TYPES, CanaryStore
from .config import Config, load_config_with_source
from .decoys import DecoyIdentity, save_identity
from .eventlog import EventLog, verify_log


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="botpolice",
        description="Defensive honeypot + canary-token system (detection and logging only).",
    )
    parser.add_argument("--version", action="version", version=f"botpolice {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="start the decoy listeners")
    run_p.add_argument("--config", default="config.json", help="path to config JSON")

    canary_p = sub.add_parser("canary", help="manage canary tokens")
    canary_sub = canary_p.add_subparsers(dest="canary_command", required=True)

    new_p = canary_sub.add_parser("new", help="generate a canary token and decoy files")
    new_p.add_argument("--placement", required=True, help="human name for where it is placed")
    new_p.add_argument("--type", choices=VALID_TYPES, default="env", help="decoy file type")
    new_p.add_argument("--config", help="read paths/address from this config")
    new_p.add_argument("--store", help="token store JSON path")
    new_p.add_argument("--out-dir", help="directory for generated decoy files")
    new_p.add_argument("--listener-url", help="address embedded in the decoy files")
    new_p.add_argument("--json", action="store_true", help="machine-readable output")

    list_p = canary_sub.add_parser("list", help="list known canary tokens")
    list_p.add_argument("--store", default="canaries.json")
    list_p.add_argument("--json", action="store_true")

    verify_p = sub.add_parser("verify-log", help="verify the hash chain of an event log")
    verify_p.add_argument("--path", default="events.jsonl", help="JSONL event log path")
    verify_p.add_argument("--json", action="store_true", help="machine-readable output")

    rotate_p = sub.add_parser(
        "rotate-decoys", help="generate a new randomized decoy identity"
    )
    rotate_p.add_argument("--config", default="config.json", help="path to config JSON")
    rotate_p.add_argument("--json", action="store_true", help="machine-readable output")

    anchor_p = sub.add_parser(
        "anchor", help="ship the current log chain head to the configured destination"
    )
    anchor_p.add_argument("--config", default="config.json", help="path to config JSON")
    anchor_p.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def _load_optional_config(path: str | None) -> Config | None:
    if not path:
        return None
    config, _ = load_config_with_source(path)
    return config


def cmd_run(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"botpolice: config not found: {config_path}", file=sys.stderr)
        print("botpolice: copy config.example.json to config.json and edit it", file=sys.stderr)
        return 2
    config, _ = load_config_with_source(config_path)

    from .server import run

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run(config))
    return 0


def cmd_canary_new(args: argparse.Namespace) -> int:
    config = _load_optional_config(args.config)

    if args.store:
        store_path = Path(args.store)
    elif config is not None:
        store_path = config.resolve(config.canary_store)
    else:
        store_path = Path("canaries.json")

    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif config is not None:
        out_dir = config.resolve(config.canary_output_dir)
    else:
        out_dir = Path("canaries")

    if args.listener_url:
        listener_url = args.listener_url
    elif config is not None:
        listener_url = config.listener_url()
    else:
        listener_url = "http://127.0.0.1:8080"

    store = CanaryStore(store_path)
    record = store.generate(args.placement, args.type, listener_url, out_dir)

    if args.json:
        print(json.dumps(record.to_dict(), indent=2))
    else:
        print(f"canary token : {record.token}")
        print(f"placement    : {record.placement}")
        print(f"type         : {record.kind}")
        print(f"file         : {record.file}")
        print(f"store        : {store_path}")
        print(f"tripwire URL : {listener_url}/t/{record.token}")
    return 0


def cmd_canary_list(args: argparse.Namespace) -> int:
    store = CanaryStore(Path(args.store))
    records = store.records()
    if args.json:
        print(json.dumps(records, indent=2))
    else:
        if not records:
            print("(no canary tokens)")
        for record in records:
            print(
                f"{record.get('token')}  placement={record.get('placement')}  "
                f"type={record.get('kind')}  file={record.get('file')}"
            )
    return 0


def cmd_verify_log(args: argparse.Namespace) -> int:
    result = verify_log(Path(args.path))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif result.ok:
        print(f"OK: {result.entries} entries, hash chain intact")
    else:
        print(
            f"BROKEN: first broken entry at line {result.first_broken_line} "
            f"({result.reason}); validated {result.entries} entries before it"
        )
    return 0 if result.ok else 1


def cmd_anchor(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"botpolice: config not found: {config_path}", file=sys.stderr)
        return 2
    config, _ = load_config_with_source(config_path)

    from .anchor import ChainAnchor

    log = EventLog(config.resolve(config.log_path))
    payload = ChainAnchor(config.anchor, config.alerts, log).anchor_once()
    if payload is None:
        print("botpolice: log is empty; nothing to anchor", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"anchored head : {payload['head']}")
        print(f"seq           : {payload['seq']}")
        print(f"delivered     : {payload['delivered']}")
    return 0


def cmd_rotate_decoys(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if config_path.exists():
        config, _ = load_config_with_source(config_path)
    else:
        config = Config.from_dict({})

    path = config.resolve(config.decoys.file)
    identity = DecoyIdentity.random()
    save_identity(path, identity)

    if args.json:
        print(json.dumps({"file": str(path), **identity.to_dict()}, indent=2))
    else:
        print(f"decoys file  : {path}")
        print(f"ssh banner   : {identity.ssh_banner}")
        print(f"http server  : {identity.http_server}")
        print(f"adb device   : {identity.adb_identity.get('ro.product.name', '-')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return cmd_run(args)
    if args.command == "canary":
        if args.canary_command == "new":
            return cmd_canary_new(args)
        if args.canary_command == "list":
            return cmd_canary_list(args)
    if args.command == "verify-log":
        return cmd_verify_log(args)
    if args.command == "rotate-decoys":
        return cmd_rotate_decoys(args)
    if args.command == "anchor":
        return cmd_anchor(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
