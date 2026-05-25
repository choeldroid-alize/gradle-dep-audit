"""Edge-case tests for the policy engine."""
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
    PolicyRule,
    PolicyViolation,
)


def _bare_row():
    """Row with no optional keys set."""
    dep = Dependency(group="org.test", artifact="core", version="0.1")
    return {"dependency": dep}


def test_missing_vulnerability_report_does_not_crash():
    violations = check_policy([_bare_row()], [rule_block_critical()])
    assert violations == []


def test_missing_risk_score_does_not_crash():
    violations = check_policy([_bare_row()], [rule_max_risk_score(10)])
    assert violations == []


def test_missing_version_info_does_not_crash():
    from gradle_dep_audit.policy import rule_no_outdated
    violations = check_policy([_bare_row()], [rule_no_outdated()])
    assert violations == []


def test_row_without_dependency_key():
    """Rows without 'dependency' key should still produce violations with 'unknown'."""
    dep = Dependency(group="g", artifact="a", version="1")
    vr = VulnerabilityReport(vulnerabilities=[{"id": "CVE-0", "severity": "CRITICAL"}])
    row = {"vulnerability_report": vr}  # no 'dependency'
    violations = check_policy([row], [rule_block_critical()])
    assert len(violations) == 1
    assert violations[0].coordinate == "unknown"


def test_custom_policy_rule():
    """Users can supply arbitrary predicate rules."""
    dep = Dependency(group="com.bad", artifact="lib", version="1.0")
    row = {"dependency": dep, "custom_flag": True}
    rule = PolicyRule(
        name="custom",
        description="custom flag set",
        predicate=lambda r: r.get("custom_flag", False),
    )
    violations = check_policy([row], [rule])
    assert len(violations) == 1
    assert violations[0].rule_name == "custom"


def test_violation_repr_does_not_crash():
    v = PolicyViolation(rule_name="r", coordinate="g:a:1", detail="d")
    assert "r" in repr(v)


def test_severity_case_insensitive():
    dep = Dependency(group="x", artifact="y", version="1")
    vr = VulnerabilityReport(vulnerabilities=[{"id": "CVE-1", "severity": "critical"}])
    row = {"dependency": dep, "vulnerability_report": vr}
    violations = check_policy([row], [rule_block_critical()])
    assert len(violations) == 1
