"""Command-line interface for gradle-dep-audit."""

from __future__ import annotations

import argparse
import sys

from gradle_dep_audit.pipeline import run_audit_from_file
from gradle_dep_audit.exporter import export
from gradle_dep_audit.filter import apply_filters


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gradle-dep-audit",
        description="Audit Gradle dependency trees for outdated or vulnerable packages.",
    )
    parser.add_argument("dep_file", help="Path to Gradle dependency tree text file.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv", "html"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument("--output", "-o", default=None, help="Write output to this file.")
    parser.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability checks.")
    parser.add_argument("--skip-outdated", action="store_true", help="Skip outdated checks.")

    # Filter options
    filter_group = parser.add_argument_group("filters")
    filter_group.add_argument("--group", default=None, help="Filter by group glob pattern.")
    filter_group.add_argument("--artifact", default=None, help="Filter by artifact glob pattern.")
    filter_group.add_argument(
        "--min-severity",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Only show vulnerabilities at or above this severity.",
    )
    filter_group.add_argument(
        "--outdated-only", action="store_true", help="Show only outdated dependencies."
    )
    filter_group.add_argument(
        "--vulnerable-only", action="store_true", help="Show only vulnerable dependencies."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    rows = run_audit_from_file(
        args.dep_file,
        skip_vuln=args.skip_vuln,
        skip_outdated=args.skip_outdated,
    )

    rows = apply_filters(
        rows,
        group_pattern=args.group,
        artifact_pattern=args.artifact,
        min_severity=args.min_severity,
        outdated_only=args.outdated_only,
        vulnerable_only=args.vulnerable_only,
    )

    export(rows, fmt=args.format, output_path=args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
