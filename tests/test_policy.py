"""Unit tests for gradle_dep_audit.policy."""
from __future__ import annotations

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.scorer import RiskScore
from gradle_dep_audit.policy import (
    check_policy,
    rule_block_critical,
    rule_max_risk_score,
    rule_no_outdated,
    PolicyViolation,
)


@pytest.fixture()
def dep():
    return Dependency(group="com.example", artifact="lib", version="1.0.0")


def _row(dep, *, severity=None, is_outdated=False, score=0):
    vulns = [{"id": "CVE-X", "severity": severity}] if severity else []
    vr = VulnerabilityReport(vulnerabilities=vulns)
    vi = VersionInfo(current="1.0.0", latest="2.0.0" if is_outdated else "1.0.0",
                     is_outdated=is_outdated)
    rs = RiskScore(score=score, label="LOW")
    return {"dependency": dep, "vulnerability_report": vr, "version_info": vi,
            "risk_score": rs}


# --- block_critical ---

def test_block_critical_fires_on_critical(dep):
    rows = [_row(dep, severity="CRITICAL")]
    violations = check_policy(rows, [rule_block_critical()])
    assert len(violations) == 1
    assert violations[0].rule_name == "block_critical"


def test_block_critical_ignores_high(dep):
    rows = [_row(dep, severity="HIGH")]
    violations = check_policy(rows, [rule_block_critical()])
    assert violations == []


def test_block_critical_clean_row(dep):
    rows = [_row(dep)]
    violations = check_policy(rows, [rule_block_critical()])
    assert violations == []


# --- max_risk_score ---

def test_max_risk_score_fires_when_exceeded(dep):
    rows = [_row(dep, score=80)]
    violations = check_policy(rows, [rule_max_risk_score(50)])
    assert len(violations) == 1
    assert violations[0].rule_name == "max_risk_score"


def test_max_risk_score_passes_at_threshold(dep):
    rows = [_row(dep, score=50)]
    violations = check_policy(rows, [rule_max_risk_score(50)])
    assert violations == []


# --- no_outdated ---

def test_no_outdated_fires_when_outdated(dep):
    rows = [_row(dep, is_outdated=True)]
    violations = check_policy(rows, [rule_no_outdated()])
    assert len(violations) == 1


def test_no_outdated_passes_when_current(dep):
    rows = [_row(dep, is_outdated=False)]
    violations = check_policy(rows, [rule_no_outdated()])
    assert violations == []


# --- multiple rules ---

def test_multiple_rules_accumulate(dep):
    rows = [_row(dep, severity="CRITICAL", is_outdated=True, score=90)]
    rules = [rule_block_critical(), rule_no_outdated(), rule_max_risk_score(50)]
    violations = check_policy(rows, rules)
    assert len(violations) == 3


def test_empty_rows_returns_no_violations():
    violations = check_policy([], [rule_block_critical()])
    assert violations == []


def test_violation_coordinate(dep):
    rows = [_row(dep, severity="CRITICAL")]
    v = check_policy(rows, [rule_block_critical()])[0]
    assert v.coordinate == dep.coordinate()
