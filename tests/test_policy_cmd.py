"""Integration tests for the policy CLI sub-command."""
from __future__ import annotations

import argparse
from unittest.mock import patch, MagicMock

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.scorer import RiskScore
from gradle_dep_audit.policy_cmd import build_policy_parser, run_policy


def _make_row(*, severity=None, is_outdated=False, score=0):
    dep = Dependency(group="com.example", artifact="lib", version="1.0.0")
    vulns = [{"id": "CVE-1", "severity": severity}] if severity else []
    vr = VulnerabilityReport(vulnerabilities=vulns)
    vi = VersionInfo(current="1.0.0", latest="2.0.0" if is_outdated else "1.0.0",
                     is_outdated=is_outdated)
    rs = RiskScore(score=score, label="LOW")
    return {"dependency": dep, "vulnerability_report": vr, "version_info": vi,
            "risk_score": rs}


@pytest.fixture()
def parser():
    p = argparse.ArgumentParser()
    subs = p.add_subparsers(dest="command")
    build_policy_parser(subs)
    return p


def _args(parser, extra: list[str] | None = None):
    base = ["policy", "fake_deps.txt"]
    return parser.parse_args(base + (extra or []))


def test_returns_zero_when_no_violations(parser, capsys):
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row()]):
        rc = run_policy(_args(parser))
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASSED" in out


def test_returns_one_on_critical_violation(parser, capsys):
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row(severity="CRITICAL")]):
        rc = run_policy(_args(parser))
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "block_critical" in out


def test_max_risk_score_flag(parser, capsys):
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row(score=99)]):
        rc = run_policy(_args(parser, ["--max-risk-score", "50"]))
    assert rc == 1


def test_no_outdated_flag(parser, capsys):
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row(is_outdated=True)]):
        rc = run_policy(_args(parser, ["--no-outdated"]))
    assert rc == 1


def test_json_output_format(parser, capsys):
    import json
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row(severity="CRITICAL")]):
        run_policy(_args(parser, ["--format", "json"]))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["rule"] == "block_critical"


def test_no_block_critical_flag_disables_rule(parser, capsys):
    with patch("gradle_dep_audit.policy_cmd.run_audit_from_file",
               return_value=[_make_row(severity="CRITICAL")]):
        rc = run_policy(_args(parser, ["--no-block-critical"]))
    assert rc == 0
