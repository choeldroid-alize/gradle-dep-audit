"""Edge-case tests for gradle_dep_audit.exporter."""

from __future__ import annotations

import json

import pytest

from gradle_dep_audit.exporter import export_json, export_csv, export_html, export
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport


def _make_row(group="g", artifact="a", version="1.0", latest=None, outdated=False, vulns=None):
    dep = Dependency(group=group, artifact=artifact, version=version)
    vi = VersionInfo(latest_version=latest, outdated=outdated)
    vr = VulnerabilityReport(purl=f"pkg:maven/{group}/{artifact}@{version}", vulnerabilities=vulns or [])
    return dep, vi, vr


def test_export_json_empty_rows():
    result = export_json([])
    assert json.loads(result) == []


def test_export_csv_empty_rows():
    result = export_csv([])
    assert "coordinate" in result
    lines = [l for l in result.splitlines() if l]
    assert len(lines) == 1  # header only


def test_export_html_empty_rows():
    result = export_html([])
    assert "<table" in result
    assert "<tr><td>" not in result


def test_export_json_no_latest_version():
    row = _make_row(latest=None)
    data = json.loads(export_json([row]))
    assert data[0]["latest_version"] is None


def test_export_html_no_vulns_shows_none():
    row = _make_row()
    result = export_html([row])
    assert "color:green" in result


def test_export_csv_multiple_vuln_ids():
    row = _make_row(
        vulns=[
            {"id": "CVE-2020-0001", "severity": "HIGH"},
            {"id": "CVE-2020-0002", "severity": "MEDIUM"},
        ]
    )
    result = export_csv([row])
    assert "CVE-2020-0001|CVE-2020-0002" in result


def test_export_case_insensitive_format():
    row = _make_row()
    result = export([row], "JSON")
    assert json.loads(result)


def test_export_html_format_via_dispatch():
    row = _make_row()
    result = export([row], "html")
    assert "<!DOCTYPE html>" in result
