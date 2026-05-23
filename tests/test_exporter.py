"""Tests for gradle_dep_audit.exporter."""

from __future__ import annotations

import json
import csv
import io
import pytest

from gradle_dep_audit.exporter import export_json, export_csv, export_html, export
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport


@pytest.fixture()
def dep_a():
    return Dependency(group="com.example", artifact="alpha", version="1.0.0")


@pytest.fixture()
def dep_b():
    return Dependency(group="org.sample", artifact="beta", version="2.3.0")


@pytest.fixture()
def vi_outdated():
    return VersionInfo(latest_version="1.5.0", outdated=True)


@pytest.fixture()
def vi_current():
    return VersionInfo(latest_version="2.3.0", outdated=False)


@pytest.fixture()
def vr_vuln():
    return VulnerabilityReport(
        purl="pkg:maven/com.example/alpha@1.0.0",
        vulnerabilities=[{"id": "CVE-2021-1234", "severity": "HIGH"}],
    )


@pytest.fixture()
def vr_clean():
    return VulnerabilityReport(
        purl="pkg:maven/org.sample/beta@2.3.0",
        vulnerabilities=[],
    )


@pytest.fixture()
def rows(dep_a, dep_b, vi_outdated, vi_current, vr_vuln, vr_clean):
    return [(dep_a, vi_outdated, vr_vuln), (dep_b, vi_current, vr_clean)]


def test_export_json_structure(rows):
    result = export_json(rows)
    data = json.loads(result)
    assert len(data) == 2
    assert data[0]["coordinate"] == "com.example:alpha:1.0.0"
    assert data[0]["outdated"] is True
    assert data[0]["vulnerabilities"][0]["id"] == "CVE-2021-1234"
    assert data[1]["vulnerabilities"] == []


def test_export_csv_header_and_rows(rows):
    result = export_csv(rows)
    reader = csv.reader(io.StringIO(result))
    header = next(reader)
    assert "coordinate" in header
    assert "vuln_ids" in header
    data_rows = list(reader)
    assert len(data_rows) == 2
    assert "CVE-2021-1234" in data_rows[0]


def test_export_html_contains_key_elements(rows):
    result = export_html(rows)
    assert "<table" in result
    assert "com.example:alpha:1.0.0" in result
    assert "CVE-2021-1234" in result
    assert "color:red" in result
    assert "color:orange" in result


def test_export_dispatch_json(rows):
    result = export(rows, "json")
    data = json.loads(result)
    assert isinstance(data, list)


def test_export_dispatch_csv(rows):
    result = export(rows, "csv")
    assert "coordinate" in result


def test_export_dispatch_html(rows):
    result = export(rows, "html")
    assert "<!DOCTYPE html>" in result


def test_export_unknown_format_raises(rows):
    with pytest.raises(ValueError, match="Unsupported export format"):
        export(rows, "xml")
