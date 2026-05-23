"""Tests for gradle_dep_audit.pipeline (including risk_score integration)."""

from unittest.mock import patch, MagicMock
import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.scorer import RiskScore
from gradle_dep_audit.pipeline import run_audit


DEPS = [
    Dependency(group="org.springframework", artifact="spring-core", version="5.3.0"),
    Dependency(group="com.fasterxml.jackson", artifact="jackson-databind", version="2.12.0"),
]


def _mock_network(monkeypatch):
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._resolve",
        lambda dep: VersionInfo(current=dep.version, latest=dep.version, is_outdated=False),
    )
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._check",
        lambda dep: VulnerabilityReport(vulnerabilities=[], vulnerable=False),
    )


def test_run_audit_returns_correct_count(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS)
    assert len(rows) == 2


def test_run_audit_row_structure(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS)
    for row in rows:
        assert "dependency" in row
        assert "version_info" in row
        assert "vuln_report" in row
        assert "risk_score" in row


def test_run_audit_risk_score_present(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS)
    for row in rows:
        assert isinstance(row["risk_score"], RiskScore)


def test_run_audit_skip_vuln_returns_empty_vulns(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS, skip_vuln=True)
    for row in rows:
        assert row["vuln_report"] is None


def test_run_audit_skip_outdated_returns_no_outdated(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS, skip_outdated=True)
    for row in rows:
        assert row["version_info"] is None


def test_run_audit_risk_score_zero_for_clean_deps(monkeypatch):
    _mock_network(monkeypatch)
    rows = run_audit(DEPS)
    for row in rows:
        assert row["risk_score"].score == 0
        assert row["risk_score"].label == "NONE"


def test_run_audit_risk_score_elevated_for_vuln(monkeypatch):
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._resolve",
        lambda dep: VersionInfo(current=dep.version, latest=dep.version, is_outdated=False),
    )
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._check",
        lambda dep: VulnerabilityReport(
            vulnerabilities=[{"id": "CVE-X", "severity": "HIGH"}],
            vulnerable=True,
        ),
    )
    rows = run_audit(DEPS[:1])
    assert rows[0]["risk_score"].score >= 7
