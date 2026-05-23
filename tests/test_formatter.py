"""Tests for gradle_dep_audit.formatter."""

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.formatter import (
    format_dependency_row,
    format_summary,
)


@pytest.fixture
def dep() -> Dependency:
    return Dependency(group="com.example", artifact="lib", version="1.0.0")


@pytest.fixture
def up_to_date_vi() -> VersionInfo:
    return VersionInfo(current_version="1.0.0", latest_version="1.0.0", is_outdated=False)


@pytest.fixture
def outdated_vi() -> VersionInfo:
    return VersionInfo(current_version="1.0.0", latest_version="2.3.0", is_outdated=True)


@pytest.fixture
def clean_report() -> VulnerabilityReport:
    return VulnerabilityReport(purl="pkg:maven/com.example/lib@1.0.0", vulnerabilities=[])


@pytest.fixture
def vuln_report() -> VulnerabilityReport:
    return VulnerabilityReport(
        purl="pkg:maven/com.example/lib@1.0.0",
        vulnerabilities=[{"id": "CVE-2023-0001", "severity": "HIGH"}],
    )


def test_format_row_up_to_date(dep, up_to_date_vi, clean_report):
    row = format_dependency_row(dep, up_to_date_vi, clean_report, use_color=False)
    assert "com.example:lib:1.0.0" in row
    assert "up-to-date" in row
    assert "vuln" not in row


def test_format_row_outdated(dep, outdated_vi, clean_report):
    row = format_dependency_row(dep, outdated_vi, clean_report, use_color=False)
    assert "outdated" in row
    assert "2.3.0" in row


def test_format_row_vulnerable(dep, up_to_date_vi, vuln_report):
    row = format_dependency_row(dep, up_to_date_vi, vuln_report, use_color=False)
    assert "1 vuln(s)" in row


def test_format_row_no_version_info(dep, vuln_report):
    row = format_dependency_row(dep, None, vuln_report, use_color=False)
    assert "com.example:lib:1.0.0" in row
    assert "1 vuln(s)" in row
    assert "outdated" not in row


def test_format_summary_counts(dep, outdated_vi, vuln_report):
    results = [(dep, outdated_vi, vuln_report)]
    summary = format_summary(results, use_color=False)
    assert "Scanned 1 dependencies" in summary
    assert "1 outdated" in summary
    assert "1 vulnerable" in summary


def test_format_summary_empty():
    summary = format_summary([], use_color=False)
    assert "Scanned 0 dependencies" in summary
    assert "0 outdated" in summary
    assert "0 vulnerable" in summary


def test_format_row_with_color(dep, outdated_vi, vuln_report):
    row = format_dependency_row(dep, outdated_vi, vuln_report, use_color=True)
    assert "\033[" in row
