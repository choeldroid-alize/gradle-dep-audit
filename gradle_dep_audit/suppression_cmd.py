"""CLI sub-command: manage the suppression list."""
from __future__ import annotations

import argparse
import json
from datetime import datetime

from gradle_dep_audit.suppression import load_suppression, save_suppression

_DATE_FMT = "%Y-%m-%d"


def build_suppression_parser(subparsers: argparse.Action) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "suppress",
        help="Add, list or remove entries in the suppression list",
    )
    p.add_argument("--file", default="suppressions.json", help="Suppression list path")
    sub = p.add_subparsers(dest="suppress_cmd", required=True)

    add_p = sub.add_parser("add", help="Add a suppression entry")
    add_p.add_argument("coordinate", help="group:artifact:version (use '*' for any version)")
    add_p.add_argument("vuln_id", help="CVE / GHSA id, or '*' to suppress all")
    add_p.add_argument("--expires", help="Expiry date YYYY-MM-DD (optional)")
    add_p.add_argument("--reason", default="", help="Human-readable reason")

    sub.add_parser("list", help="Print all active suppression entries")

    rm_p = sub.add_parser("remove", help="Remove a suppression entry")
    rm_p.add_argument("coordinate")
    rm_p.add_argument("vuln_id")

    return p


def run_suppression(args: argparse.Namespace) -> int:
    suppressions = load_suppression(args.file)

    if args.suppress_cmd == "add":
        if args.expires:
            try:
                datetime.strptime(args.expires, _DATE_FMT)
            except ValueError:
                print(f"ERROR: --expires must be YYYY-MM-DD, got {args.expires!r}")
                return 1
        entry: dict = {"coordinate": args.coordinate, "vuln_id": args.vuln_id}
        if args.expires:
            entry["expires"] = args.expires
        if args.reason:
            entry["reason"] = args.reason
        suppressions.append(entry)
        save_suppression(args.file, suppressions)
        print(f"Added suppression for {args.coordinate} / {args.vuln_id}")
        return 0

    if args.suppress_cmd == "list":
        if not suppressions:
            print("No suppressions defined.")
            return 0
        for e in suppressions:
            expires = e.get("expires", "never")
            reason = e.get("reason", "")
            print(f"  {e['coordinate']}  {e['vuln_id']}  expires={expires}  {reason}")
        return 0

    if args.suppress_cmd == "remove":
        before = len(suppressions)
        suppressions = [
            e for e in suppressions
            if not (e["coordinate"] == args.coordinate and e["vuln_id"] == args.vuln_id)
        ]
        if len(suppressions) == before:
            print("No matching entry found.")
            return 1
        save_suppression(args.file, suppressions)
        print(f"Removed suppression for {args.coordinate} / {args.vuln_id}")
        return 0

    return 1
