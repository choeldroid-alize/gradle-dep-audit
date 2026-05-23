"""Group audit rows by various dimensions for summary reporting."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Any


def group_by_group(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group audit rows by the Maven group ID (e.g. 'org.springframework')."""
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        dep = row.get("dependency")
        key = dep.group if dep else "unknown"
        result[key].append(row)
    return dict(result)


def group_by_severity(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group audit rows by the highest vulnerability severity present.

    Rows with no vulnerabilities are placed under the key 'NONE'.
    """
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        report = row.get("vuln_report")
        if report and report.vulnerabilities:
            severities = [
                v.get("severity", "UNKNOWN").upper()
                for v in report.vulnerabilities
            ]
            priority = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            top = next((s for s in priority if s in severities), "UNKNOWN")
        else:
            top = "NONE"
        result[top].append(row)
    return dict(result)


def group_by_status(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group audit rows by their version status: 'outdated', 'current', or 'unknown'."""
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        vi = row.get("version_info")
        if vi is None:
            key = "unknown"
        elif vi.is_outdated:
            key = "outdated"
        else:
            key = "current"
        result[key].append(row)
    return dict(result)


def summarize_groups(grouped: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    """Return a mapping of group key -> count of rows."""
    return {k: len(v) for k, v in grouped.items()}
