"""CLI sub-command: remediation — print upgrade advice for audit results."""

import argparse
import json
import sys
from typing import List

from gradle_dep_audit.pipeline import run_audit_from_file
from gradle_dep_audit.remediation import RemediationAdvice, build_remediation_plan


def build_remediation_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # noqa: SLF001
    p = subparsers.add_parser(
        "remediation",
        help="Print upgrade/remediation advice for outdated or vulnerable dependencies.",
    )
    p.add_argument("dep_tree", help="Path to Gradle dependency tree text file.")
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--skip-vuln",
        action="store_true",
        default=False,
        help="Skip vulnerability checks (faster, offline).",
    )
    return p


def _print_text(plan: List[RemediationAdvice]) -> None:
    if not plan:
        print("\u2705  No remediation actions required.")
        return
    print(f"{'Dependency':<45} {'Current':<15} {'Suggested':<15} Reasons")
    print("-" * 100)
    for advice in plan:
        coord = advice.dependency.coordinate()
        suggested = advice.suggested_version or "(none)"
        reasons = "; ".join(advice.reasons)
        print(f"{coord:<45} {advice.current_version:<15} {suggested:<15} {reasons}")
        if advice.vuln_ids:
            print(f"  {'Vuln IDs:':<43} {', '.join(advice.vuln_ids)}")


def _print_json(plan: List[RemediationAdvice]) -> None:
    output = [
        {
            "dependency": adv.dependency.coordinate(),
            "current_version": adv.current_version,
            "suggested_version": adv.suggested_version,
            "reasons": adv.reasons,
            "vuln_ids": adv.vuln_ids,
        }
        for adv in plan
    ]
    print(json.dumps(output, indent=2))


def run_remediation(args: argparse.Namespace) -> int:
    try:
        rows = run_audit_from_file(
            args.dep_tree,
            skip_vuln=args.skip_vuln,
        )
    except FileNotFoundError:
        print(f"Error: file not found: {args.dep_tree}", file=sys.stderr)
        return 2

    plan = build_remediation_plan(rows)

    if args.format == "json":
        _print_json(plan)
    else:
        _print_text(plan)

    return 1 if plan else 0
