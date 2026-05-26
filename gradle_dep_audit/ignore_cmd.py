"""CLI sub-command: manage per-project ignore rules for specific dependencies."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

DEFAULT_IGNORE_FILE = ".gradle-dep-audit-ignore.json"


def build_ignore_parser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "ignore",
        help="Add, remove, or list dependency ignore rules.",
    )
    sub = p.add_subparsers(dest="ignore_action", required=True)

    add_p = sub.add_parser("add", help="Ignore a dependency coordinate (group:artifact).")
    add_p.add_argument("coordinate", help="e.g. org.springframework:spring-core")
    add_p.add_argument("--reason", default="", help="Optional human-readable reason.")
    add_p.add_argument("--file", default=DEFAULT_IGNORE_FILE, help="Ignore file path.")

    rm_p = sub.add_parser("remove", help="Remove an ignore rule.")
    rm_p.add_argument("coordinate", help="Coordinate to un-ignore.")
    rm_p.add_argument("--file", default=DEFAULT_IGNORE_FILE, help="Ignore file path.")

    ls_p = sub.add_parser("list", help="List all active ignore rules.")
    ls_p.add_argument("--file", default=DEFAULT_IGNORE_FILE, help="Ignore file path.")

    return p


def _load(path: str) -> List[dict]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open() as fh:
        return json.load(fh)


def _save(path: str, entries: List[dict]) -> None:
    with Path(path).open("w") as fh:
        json.dump(entries, fh, indent=2)


def run_ignore(args: argparse.Namespace) -> int:
    action = args.ignore_action
    ignore_file = args.file

    if action == "add":
        entries = _load(ignore_file)
        coord = args.coordinate
        if any(e["coordinate"] == coord for e in entries):
            print(f"[ignore] '{coord}' is already ignored.", file=sys.stderr)
            return 1
        entries.append({"coordinate": coord, "reason": args.reason})
        _save(ignore_file, entries)
        print(f"[ignore] Added ignore rule for '{coord}'.")
        return 0

    if action == "remove":
        entries = _load(ignore_file)
        coord = args.coordinate
        new_entries = [e for e in entries if e["coordinate"] != coord]
        if len(new_entries) == len(entries):
            print(f"[ignore] No rule found for '{coord}'.", file=sys.stderr)
            return 1
        _save(ignore_file, new_entries)
        print(f"[ignore] Removed ignore rule for '{coord}'.")
        return 0

    if action == "list":
        entries = _load(ignore_file)
        if not entries:
            print("[ignore] No ignore rules defined.")
        else:
            for e in entries:
                reason = f"  # {e['reason']}" if e.get("reason") else ""
                print(f"  {e['coordinate']}{reason}")
        return 0

    print(f"[ignore] Unknown action: {action}", file=sys.stderr)
    return 2
