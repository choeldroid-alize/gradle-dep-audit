"""Render a TrendReport to the terminal or as JSON."""

from __future__ import annotations

import json
from typing import TextIO
import sys

from gradle_dep_audit.trend import TrendReport

_BAR_WIDTH = 30


def _bar(value: int, max_value: int, width: int = _BAR_WIDTH) -> str:
    if max_value == 0:
        return ""
    filled = round(value / max_value * width)
    return "█" * filled + "░" * (width - filled)


def print_trend_text(report: TrendReport, out: TextIO = sys.stdout) -> None:
    if not report.points:
        out.write("No trend data available.\n")
        return

    max_vuln = max((p.vulnerable for p in report.points), default=1) or 1
    max_outdated = max((p.outdated for p in report.points), default=1) or 1

    out.write(f"{'Snapshot':<30} {'Total':>6} {'Outdated':>9} {'Vulnerable':>11}\n")
    out.write("-" * 62 + "\n")
    for p in report.points:
        out.write(
            f"{p.label:<30} {p.total:>6} {p.outdated:>9} {p.vulnerable:>11}\n"
        )
        out.write(f"  vuln    [{_bar(p.vulnerable, max_vuln)}]\n")
        out.write(f"  outdated[{_bar(p.outdated, max_outdated)}]\n")

    out.write("\n")
    delta = report.delta_vulnerable
    direction = "improved" if delta < 0 else ("worsened" if delta > 0 else "unchanged")
    out.write(f"Overall trend: {direction} (Δvulnerable={delta:+d})\n")


def print_trend_json(report: TrendReport, out: TextIO = sys.stdout) -> None:
    payload = {
        "improving": report.improving,
        "delta_vulnerable": report.delta_vulnerable,
        "points": [
            {
                "label": p.label,
                "total": p.total,
                "outdated": p.outdated,
                "vulnerable": p.vulnerable,
                "critical": p.critical,
                "high": p.high,
            }
            for p in report.points
        ],
    }
    out.write(json.dumps(payload, indent=2) + "\n")
