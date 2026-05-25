"""CLI helper: run an audit diff against a baseline snapshot and send Slack alerts."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from gradle_dep_audit.differ import diff_results
from gradle_dep_audit.notifier import build_payload, send_slack
from gradle_dep_audit.pipeline import run_audit_from_file
from gradle_dep_audit.snapshot import load_snapshot, save_snapshot


def build_notify_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gradle-dep-notify",
        description="Audit a Gradle dependency tree and send Slack alerts on regressions.",
    )
    p.add_argument("dep_tree", help="Path to gradle dependency tree text file.")
    p.add_argument(
        "--baseline-snapshot",
        metavar="SNAPSHOT",
        help="Path to a previously saved JSON snapshot to diff against.",
    )
    p.add_argument(
        "--save-snapshot",
        metavar="OUT",
        help="Save current audit results to this snapshot path.",
    )
    p.add_argument(
        "--slack-webhook",
        metavar="URL",
        help="Slack incoming webhook URL.  If omitted, prints payload to stdout.",
    )
    p.add_argument(
        "--skip-vuln",
        action="store_true",
        help="Skip vulnerability checks (OSS Index).",
    )
    p.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="Exit with code 1 when new issues are found.",
    )
    return p


def run_notify(argv: Optional[List[str]] = None) -> int:
    """Entry-point for the notify command.  Returns an exit code."""
    parser = build_notify_parser()
    args = parser.parse_args(argv)

    # 1. Run current audit
    current_rows = run_audit_from_file(args.dep_tree, skip_vuln=args.skip_vuln)

    # 2. Optionally save snapshot
    if args.save_snapshot:
        save_snapshot(current_rows, args.save_snapshot)

    # 3. Diff against baseline snapshot
    if args.baseline_snapshot:
        try:
            baseline_rows = load_snapshot(args.baseline_snapshot)
        except FileNotFoundError:
            print(f"[warn] baseline snapshot not found: {args.baseline_snapshot}", file=sys.stderr)
            baseline_rows = []
    else:
        baseline_rows = []

    diff = diff_results(baseline_rows, current_rows)
    payload = build_payload(diff)

    # 4. Notify
    if args.slack_webhook:
        ok = send_slack(payload, args.slack_webhook)
        if not ok:
            print("[error] Failed to send Slack notification.", file=sys.stderr)
    else:
        import json as _json
        print(_json.dumps(payload.to_dict(), indent=2))

    # 5. Exit code
    if args.fail_on_alert and not payload.is_empty():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_notify())
