"""Filtering utilities for audit results based on severity, scope, and patterns."""

from __future__ import annotations

import fnmatch
import re
from typing import List, Optional

from gradle_dep_audit.parser import Dependency


SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def filter_by_group(rows: List[dict], pattern: str) -> List[dict]:
    """Keep only rows whose group matches the given glob pattern."""
    return [
        row for row in rows
        if fnmatch.fnmatch(row["dependency"].group, pattern)
    ]


def filter_by_artifact(rows: List[dict], pattern: str) -> List[dict]:
    """Keep only rows whose artifact name matches the given glob pattern."""
    return [
        row for row in rows
        if fnmatch.fnmatch(row["dependency"].artifact, pattern)
    ]


def filter_by_min_severity(rows: List[dict], min_severity: str) -> List[dict]:
    """Keep only rows with at least one vulnerability at or above *min_severity*."""
    threshold = SEVERITY_LEVELS.get(min_severity.lower(), 0)
    result = []
    for row in rows:
        report = row.get("vuln_report")
        if report is None:
            continue
        for vuln in report.vulnerabilities:
            sev = vuln.get("severity", "").lower()
            if SEVERITY_LEVELS.get(sev, 0) >= threshold:
                result.append(row)
                break
    return result


def filter_outdated_only(rows: List[dict]) -> List[dict]:
    """Keep only rows where the dependency is outdated."""
    return [
        row for row in rows
        if row.get("version_info") and row["version_info"].is_outdated
    ]


def filter_vulnerable_only(rows: List[dict]) -> List[dict]:
    """Keep only rows that have at least one reported vulnerability."""
    return [
        row for row in rows
        if row.get("vuln_report") and row["vuln_report"].is_vulnerable
    ]


def apply_filters(
    rows: List[dict],
    *,
    group_pattern: Optional[str] = None,
    artifact_pattern: Optional[str] = None,
    min_severity: Optional[str] = None,
    outdated_only: bool = False,
    vulnerable_only: bool = False,
) -> List[dict]:
    """Apply all requested filters in sequence and return the filtered list."""
    if group_pattern:
        rows = filter_by_group(rows, group_pattern)
    if artifact_pattern:
        rows = filter_by_artifact(rows, artifact_pattern)
    if min_severity:
        rows = filter_by_min_severity(rows, min_severity)
    if outdated_only:
        rows = filter_outdated_only(rows)
    if vulnerable_only:
        rows = filter_vulnerable_only(rows)
    return rows
