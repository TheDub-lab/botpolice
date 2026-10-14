"""Command-line interface for botpolice.

    botpolice run --config config.json
    botpolice canary new --placement <name> --type env|aws|ssh|json|tripwire
    botpolice canary list [--store canaries.json]
    botpolice verify-log --path events.jsonl
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
from .eventlog import verify_log


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

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
