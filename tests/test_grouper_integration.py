"""Integration-style tests for grouper using realistic pipeline row shapes."""

from unittest.mock import MagicMock
from gradle_dep_audit.grouper import (
    group_by_group,
    group_by_severity,
    group_by_status,
    summarize_groups,
)


def _row(group, artifact, version, severity=None, outdated=False):
    dep = MagicMock(group=group, artifact=artifact, version=version)
    vi = MagicMock(is_outdated=outdated, latest_version="2.0.0" if outdated else version)
    vr = MagicMock()
    vr.vulnerabilities = [{"severity": severity, "id": "CVE-TEST"}] if severity else []
    return {"dependency": dep, "version_info": vi, "vuln_report": vr, "risk_score": MagicMock()}


ROWS = [
    _row("org.springframework", "spring-core", "5.3.0", severity="HIGH", outdated=True),
    _row("org.springframework", "spring-web", "5.3.0", severity="MEDIUM", outdated=True),
    _row("com.fasterxml.jackson", "jackson-databind", "2.13.0", severity="CRITICAL"),
    _row("com.google.guava", "guava", "31.0"),
    _row("com.google.guava", "guava-testlib", "31.0", outdated=True),
]


def test_full_group_by_group_counts():
    grouped = group_by_group(ROWS)
    summary = summarize_groups(grouped)
    assert summary["org.springframework"] == 2
    assert summary["com.fasterxml.jackson"] == 1
    assert summary["com.google.guava"] == 2


def test_full_group_by_severity_distribution():
    grouped = group_by_severity(ROWS)
    assert "CRITICAL" in grouped
    assert "HIGH" in grouped
    assert "MEDIUM" in grouped
    assert "NONE" in grouped
    # guava (no vuln, not outdated) and guava-testlib (no vuln) -> NONE
    assert len(grouped["NONE"]) == 2


def test_full_group_by_status_distribution():
    grouped = group_by_status(ROWS)
    assert len(grouped.get("outdated", [])) == 3
    assert len(grouped.get("current", [])) == 2


def test_summarize_after_severity_grouping():
    grouped = group_by_severity(ROWS)
    summary = summarize_groups(grouped)
    total = sum(summary.values())
    assert total == len(ROWS)


def test_summarize_after_status_grouping():
    grouped = group_by_status(ROWS)
    summary = summarize_groups(grouped)
    assert sum(summary.values()) == len(ROWS)
