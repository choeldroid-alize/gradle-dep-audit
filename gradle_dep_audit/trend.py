"""Trend analysis: compare multiple snapshots over time to detect worsening/improving posture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional

from gradle_dep_audit.snapshot import load_snapshot


@dataclass
class TrendPoint:
    label: str
    total: int
    outdated: int
    vulnerable: int
    critical: int
    high: int

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"TrendPoint(label={self.label!r}, total={self.total}, "
            f"outdated={self.outdated}, vulnerable={self.vulnerable})"
        )


@dataclass
class TrendReport:
    points: List[TrendPoint] = field(default_factory=list)

    @property
    def improving(self) -> Optional[bool]:
        """Return True if vulnerability count decreased from first to last point."""
        if len(self.points) < 2:
            return None
        return self.points[-1].vulnerable < self.points[0].vulnerable

    @property
    def delta_vulnerable(self) -> int:
        if len(self.points) < 2:
            return 0
        return self.points[-1].vulnerable - self.points[0].vulnerable


def _point_from_rows(label: str, rows: list) -> TrendPoint:
    total = len(rows)
    outdated = sum(1 for r in rows if r.get("is_outdated", False))
    vulns = [r for r in rows if r.get("vulnerabilities")]
    vulnerable = len(vulns)
    critical = sum(
        1 for r in vulns
        for v in r["vulnerabilities"]
        if (v.get("severity") or "").upper() == "CRITICAL"
    )
    high = sum(
        1 for r in vulns
        for v in r["vulnerabilities"]
        if (v.get("severity") or "").upper() == "HIGH"
    )
    return TrendPoint(label=label, total=total, outdated=outdated,
                      vulnerable=vulnerable, critical=critical, high=high)


def build_trend(snapshot_labels: List[str], snapshots_dir: str = ".gradle_dep_audit") -> TrendReport:
    """Load each named snapshot and build a TrendReport."""
    report = TrendReport()
    for label in snapshot_labels:
        rows = load_snapshot(label, snapshots_dir=snapshots_dir)
        report.points.append(_point_from_rows(label, rows))
    return report
