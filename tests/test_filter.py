"""Tests for gradle_dep_audit.filter module."""

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.filter import (
    apply_filters,
    filter_by_group,
    filter_by_artifact,
    filter_by_min_severity,
    filter_outdated_only,
    filter_vulnerable_only,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def dep_spring():
    return Dependency(group="org.springframework", artifact="spring-core", version="5.3.0")


@pytest.fixture
def dep_jackson():
    return Dependency(group="com.fasterxml.jackson", artifact="jackson-databind", version="2.13.0")


@pytest.fixture
def vi_outdated():
    return VersionInfo(current="5.3.0", latest="5.3.27", is_outdated=True)


@pytest.fixture
def vi_current():
    return VersionInfo(current="2.13.0", latest="2.13.0", is_outdated=False)


@pytest.fixture
def vr_high():
    return VulnerabilityReport(
        is_vulnerable=True,
        vulnerabilities=[{"id": "CVE-2022-0001", "severity": "HIGH"}],
    )


@pytest.fixture
def vr_clean():
    return VulnerabilityReport(is_vulnerable=False, vulnerabilities=[])


@pytest.fixture
def rows(dep_spring, dep_jackson, vi_outdated, vi_current, vr_high, vr_clean):
    return [
        {"dependency": dep_spring, "version_info": vi_outdated, "vuln_report": vr_high},
        {"dependency": dep_jackson, "version_info": vi_current, "vuln_report": vr_clean},
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_filter_by_group_matches(rows):
    result = filter_by_group(rows, "org.springframework")
    assert len(result) == 1
    assert result[0]["dependency"].group == "org.springframework"


def test_filter_by_group_glob(rows):
    result = filter_by_group(rows, "com.fasterxml.*")
    assert len(result) == 1


def test_filter_by_group_no_match(rows):
    assert filter_by_group(rows, "io.netty") == []


def test_filter_by_artifact(rows):
    result = filter_by_artifact(rows, "jackson-*")
    assert len(result) == 1
    assert result[0]["dependency"].artifact == "jackson-databind"


def test_filter_by_min_severity_high(rows):
    result = filter_by_min_severity(rows, "high")
    assert len(result) == 1
    assert result[0]["vuln_report"].is_vulnerable is True


def test_filter_by_min_severity_critical_returns_empty(rows):
    assert filter_by_min_severity(rows, "critical") == []


def test_filter_outdated_only(rows):
    result = filter_outdated_only(rows)
    assert len(result) == 1
    assert result[0]["version_info"].is_outdated is True


def test_filter_vulnerable_only(rows):
    result = filter_vulnerable_only(rows)
    assert len(result) == 1
    assert result[0]["vuln_report"].is_vulnerable is True


def test_apply_filters_combined(rows):
    result = apply_filters(rows, group_pattern="org.*", outdated_only=True)
    assert len(result) == 1


def test_apply_filters_no_filters_returns_all(rows):
    assert apply_filters(rows) == rows


def test_apply_filters_empty_input():
    assert apply_filters([], outdated_only=True, vulnerable_only=True) == []
