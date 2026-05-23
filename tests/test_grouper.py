"""Tests for gradle_dep_audit.grouper."""

import pytest
from unittest.mock import MagicMock

from gradle_dep_audit.grouper import (
    group_by_group,
    group_by_severity,
    group_by_status,
    summarize_groups,
)


def _make_dep(group: str, artifact: str = "artifact", version: str = "1.0.0"):
    dep = MagicMock()
    dep.group = group
    dep.artifact = artifact
    dep.version = version
    return dep


def _make_row(group="org.example", artifact="lib", version="1.0",
              severity=None, is_outdated=False):
    dep = _make_dep(group, artifact, version)

    vi = MagicMock()
    vi.is_outdated = is_outdated

    vuln_report = MagicMock()
    if severity:
        vuln_report.vulnerabilities = [{"severity": severity, "id": "CVE-0000"}]
    else:
        vuln_report.vulnerabilities = []

    return {"dependency": dep, "version_info": vi, "vuln_report": vuln_report}


# --- group_by_group ---

def test_group_by_group_single():
    rows = [_make_row(group="org.spring"), _make_row(group="org.spring")]
    result = group_by_group(rows)
    assert "org.spring" in result
    assert len(result["org.spring"]) == 2


def test_group_by_group_multiple():
    rows = [_make_row(group="com.google"), _make_row(group="org.spring")]
    result = group_by_group(rows)
    assert set(result.keys()) == {"com.google", "org.spring"}


def test_group_by_group_no_dep():
    rows = [{"dependency": None, "version_info": None, "vuln_report": None}]
    result = group_by_group(rows)
    assert "unknown" in result


# --- group_by_severity ---

def test_group_by_severity_critical():
    rows = [_make_row(severity="CRITICAL")]
    result = group_by_severity(rows)
    assert "CRITICAL" in result


def test_group_by_severity_none():
    rows = [_make_row(severity=None)]
    result = group_by_severity(rows)
    assert "NONE" in result


def test_group_by_severity_high_beats_medium():
    row = _make_row()
    row["vuln_report"].vulnerabilities = [
        {"severity": "MEDIUM"},
        {"severity": "HIGH"},
    ]
    result = group_by_severity([row])
    assert "HIGH" in result


# --- group_by_status ---

def test_group_by_status_outdated():
    rows = [_make_row(is_outdated=True)]
    result = group_by_status(rows)
    assert "outdated" in result


def test_group_by_status_current():
    rows = [_make_row(is_outdated=False)]
    result = group_by_status(rows)
    assert "current" in result


def test_group_by_status_unknown():
    row = _make_row()
    row["version_info"] = None
    result = group_by_status([row])
    assert "unknown" in result


# --- summarize_groups ---

def test_summarize_groups():
    rows = [_make_row(group="a"), _make_row(group="a"), _make_row(group="b")]
    grouped = group_by_group(rows)
    summary = summarize_groups(grouped)
    assert summary == {"a": 2, "b": 1}


def test_summarize_groups_empty():
    assert summarize_groups({}) == {}
