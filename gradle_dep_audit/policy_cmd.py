"""CLI sub-command: enforce policy rules on an audit snapshot or live run."""
from __future__ import annotations

import argparse
import json
import sys

from gradle_dep_audit.pipeline import run_audit_from_file
from gradle_dep_audit.policy import (
    check_policy,
    rule_block_critical,
    rule_max_risk_score,
    rule_no_outdated,
)


def build_policy_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = subparsers.add_parser(
        "policy",
        help="Enforce policy rules and exit non-zero on violations",
    )
    p.add_argument("dep_file", help="Path to Gradle dependency tree text file")
    p.add_argument("--block-critical", action="store_true", default=True,
                   help="Fail on CRITICAL vulnerabilities (default: on)")
    p.add_argument("--no-block-critical", dest="block_critical", action="store_false")
    p.add_argument("--max-risk-score", type=int, default=None, metavar="N",
                   help="Fail when risk score > N")
    p.add_argument("--no-outdated", action="store_true", default=False,
                   help="Fail on any outdated dependency")
    p.add_argument("--format", choices=["text", "json"], default="text")
    return p


def run_policy(args: argparse.Namespace) -> int:
    rows = run_audit_from_file(args.dep_file)

    rules = []
    if args.block_critical:
        rules.append(rule_block_critical())
    if args.max_risk_score is not None:
        rules.append(rule_max_risk_score(args.max_risk_score))
    if args.no_outdated:
        rules.append(rule_no_outdated())

    violations = check_policy(rows, rules)

    if args.format == "json":
        print(json.dumps([{"rule": v.rule_name, "coordinate": v.coordinate,
                           "detail": v.detail} for v in violations], indent=2))
    else:
        if violations:
            print(f"Policy check FAILED — {len(violations)} violation(s):")
            for v in violations:
                print(f"  [{v.rule_name}] {v.coordinate}: {v.detail}")
        else:
            print("Policy check PASSED — no violations found.")

    return 1 if violations else 0


if __name__ == "__main__":  # pragma: no cover
    import argparse as _ap
    _parser = _ap.ArgumentParser()
    _subs = _parser.add_subparsers(dest="command")
    build_policy_parser(_subs)
    _args = _parser.parse_args()
    sys.exit(run_policy(_args))
