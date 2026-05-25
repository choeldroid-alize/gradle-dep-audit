"""Diff two audit result sets to highlight changes between runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class DiffResult:
    """Holds the delta between two audit snapshots."""

    added: List[dict] = field(default_factory=list)
    removed: List[dict] = field(default_factory=list)
    upgraded: List[Tuple[dict, dict]] = field(default_factory=list)
    newly_vulnerable: List[dict] = field(default_factory=list)
    resolved_vulnerabilities: List[dict] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"DiffResult(added={len(self.added)}, removed={len(self.removed)}, "
            f"upgraded={len(self.upgraded)}, newly_vulnerable={len(self.newly_vulnerable)}, "
            f"resolved_vulnerabilities={len(self.resolved_vulnerabilities)})"
        )


def _row_key(row: dict) -> str:
    """Return a stable identity key for a result row."""
    dep = row.get("dependency")
    if dep is None:
        return ""
    return dep.coordinate()


def _vuln_ids(row: dict) -> set:
    """Extract vulnerability IDs from a result row."""
    vr = row.get("vulnerability_report")
    if vr is None or not vr.vulnerabilities:
        return set()
    return {v.get("id", "") for v in vr.vulnerabilities}


def diff_results(before: List[dict], after: List[dict]) -> DiffResult:
    """Compare two lists of audit rows and return a DiffResult.

    Args:
        before: Audit rows from the previous run.
        after:  Audit rows from the current run.

    Returns:
        A DiffResult describing what changed.
    """
    before_map: Dict[str, dict] = {_row_key(r): r for r in before}
    after_map: Dict[str, dict] = {_row_key(r): r for r in after}

    result = DiffResult()

    for key, row in after_map.items():
        if key not in before_map:
            result.added.append(row)
            if _vuln_ids(row):
                result.newly_vulnerable.append(row)
        else:
            old_row = before_map[key]
            old_latest = (old_row.get("version_info") or object()).__dict__.get("latest")
            new_latest = (row.get("version_info") or object()).__dict__.get("latest")
            dep = row.get("dependency")
            old_dep = old_row.get("dependency")
            if dep and old_dep and dep.version != old_dep.version:
                result.upgraded.append((old_row, row))

            old_vulns = _vuln_ids(old_row)
            new_vulns = _vuln_ids(row)
            if new_vulns - old_vulns:
                result.newly_vulnerable.append(row)
            if old_vulns - new_vulns:
                result.resolved_vulnerabilities.append(row)

    for key, row in before_map.items():
        if key not in after_map:
            result.removed.append(row)

    return result
