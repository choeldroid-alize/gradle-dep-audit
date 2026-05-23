"""Tests for gradle_dep_audit.scorer."""

import pytest

from gradle_dep_audit.scorer import RiskScore, compute_score
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.parser import Dependency


@pytest.fixture
def dep():
    return Dependency(group="com.example", artifact="lib", version="1.0.0")


@pytest.fixture
def vi_outdated():
    return VersionInfo(current="1.0.0", latest="2.3.0", is_outdated=True)


@pytest.fixture
def vi_current():
    return VersionInfo(current="2.3.0", latest="2.3.0", is_outdated=False)


@pytest.fixture
def vr_critical():
    return VulnerabilityReport(
        vulnerabilities=[{"id": "CVE-2024-001", "severity": "CRITICAL"}],
        vulnerable=True,
    )


@pytest.fixture
def vr_high():
    return VulnerabilityReport(
        vulnerabilities=[{"id": "CVE-2024-002", "severity": "HIGH"}],
        vulnerable=True,
    )


@pytest.fixture
def vr_clean():
    return VulnerabilityReport(vulnerabilities=[], vulnerable=False)


def test_no_issues_gives_zero_score(vi_current, vr_clean):
    rs = compute_score(vi_current, vr_clean)
    assert rs.score == 0
    assert rs.label == "NONE"
    assert rs.reasons == []


def test_critical_vuln_score(vi_current, vr_critical):
    rs = compute_score(vi_current, vr_critical)
    assert rs.score >= 10
    assert rs.label == "CRITICAL"
    assert any("Critical" in r for r in rs.reasons)


def test_high_vuln_score(vi_current, vr_high):
    rs = compute_score(vi_current, vr_high)
    assert rs.score == 7
    assert rs.label == "HIGH"


def test_outdated_minor_score(vi_outdated, vr_clean):
    vi = VersionInfo(current="1.2.0", latest="1.5.0", is_outdated=True)
    rs = compute_score(vi, vr_clean)
    assert rs.score == 3
    assert rs.label == "LOW"


def test_outdated_major_score(vr_clean):
    vi = VersionInfo(current="1.0.0", latest="3.0.0", is_outdated=True)
    rs = compute_score(vi, vr_clean)
    # 3 (outdated) + 4 (major behind) = 7
    assert rs.score == 7
    assert any("Major" in r for r in rs.reasons)


def test_combined_vuln_and_outdated(vr_high):
    vi = VersionInfo(current="1.0.0", latest="2.0.0", is_outdated=True)
    rs = compute_score(vi, vr_high)
    # 7 (high) + 3 (outdated) + 4 (major) = 14
    assert rs.score == 14
    assert rs.label == "CRITICAL"


def test_none_inputs_give_zero():
    rs = compute_score(None, None)
    assert rs.score == 0
    assert rs.label == "NONE"


def test_risk_score_repr():
    rs = RiskScore(score=5, reasons=["test"])
    assert "5" in repr(rs)
