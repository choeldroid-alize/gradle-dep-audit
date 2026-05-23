"""Edge-case tests for gradle_dep_audit.scorer."""

import pytest

from gradle_dep_audit.scorer import compute_score, RiskScore
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport


def test_multiple_vulns_accumulate():
    vr = VulnerabilityReport(
        vulnerabilities=[
            {"id": "CVE-1", "severity": "HIGH"},
            {"id": "CVE-2", "severity": "MEDIUM"},
            {"id": "CVE-3", "severity": "LOW"},
        ],
        vulnerable=True,
    )
    vi = VersionInfo(current="1.0", latest="1.0", is_outdated=False)
    rs = compute_score(vi, vr)
    assert rs.score == 7 + 4 + 1
    assert len(rs.reasons) == 3


def test_unknown_severity_treated_as_low():
    vr = VulnerabilityReport(
        vulnerabilities=[{"id": "CVE-X", "severity": "UNKNOWN"}],
        vulnerable=True,
    )
    vi = VersionInfo(current="1.0", latest="1.0", is_outdated=False)
    rs = compute_score(vi, vr)
    assert rs.score == 1


def test_missing_severity_key_treated_as_low():
    vr = VulnerabilityReport(
        vulnerabilities=[{"id": "CVE-Y"}],
        vulnerable=True,
    )
    vi = VersionInfo(current="1.0", latest="1.0", is_outdated=False)
    rs = compute_score(vi, vr)
    assert rs.score == 1


def test_non_numeric_version_does_not_crash():
    vi = VersionInfo(current="abc", latest="xyz", is_outdated=True)
    vr = VulnerabilityReport(vulnerabilities=[], vulnerable=False)
    rs = compute_score(vi, vr)
    # outdated weight only, no major bonus
    assert rs.score == 3


def test_label_boundaries():
    assert RiskScore(score=0, reasons=[]).label == "NONE"
    assert RiskScore(score=1, reasons=[]).label == "LOW"
    assert RiskScore(score=4, reasons=[]).label == "MEDIUM"
    assert RiskScore(score=7, reasons=[]).label == "HIGH"
    assert RiskScore(score=10, reasons=[]).label == "CRITICAL"


def test_empty_vulnerability_list_gives_zero():
    vr = VulnerabilityReport(vulnerabilities=[], vulnerable=False)
    vi = VersionInfo(current="2.0", latest="2.0", is_outdated=False)
    rs = compute_score(vi, vr)
    assert rs.score == 0
