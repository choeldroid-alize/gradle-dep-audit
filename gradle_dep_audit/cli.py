"""Command-line interface for gradle-dep-audit."""

import argparse
import sys
from pathlib import Path

from .parser import parse_dependency_tree
from .checker import check_vulnerabilities
from .report import print_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gradle-dep-audit",
        description="Scan Gradle dependency trees for outdated or vulnerable packages.",
    )
    p.add_argument(
        "input",
        metavar="FILE",
        help="Path to gradle dependency tree text file (use '-' for stdin).",
    )
    p.add_argument(
        "--token",
        metavar="TOKEN",
        default=None,
        help="OSS Index API token for authenticated requests.",
    )
    p.add_argument(
        "--fail-on-vuln",
        action="store_true",
        default=False,
        help="Exit with non-zero status if any vulnerabilities are found.",
    )
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.input == "-":
        text = sys.stdin.read()
    else:
        path = Path(args.input)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        text = path.read_text(encoding="utf-8")

    deps = parse_dependency_tree(text)
    if not deps:
        print("No dependencies found in input.", file=sys.stderr)
        return 0

    reports = check_vulnerabilities(deps, token=args.token)
    print_report(reports, fmt=args.format)

    if args.fail_on_vuln and any(r.is_vulnerable for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
