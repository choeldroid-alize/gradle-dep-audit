"""Tests for gradle_dep_audit.remediation and remediation_cmd."""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.remediation import (
    RemediationAdvice,
    build_advice,
    build_remediation_plan,
)
from gradle_dep_audit.remediation_cmd import build_remediation_parser, run_remediation


@pytest.fixture
def dep():
    return Dependency(group="org.example", artifact="lib", version="1.0.0")


@pytest.fixture
def vi_outdated():
    return VersionInfo(latest_version="2.0.0", is_outdated=True)


@pytest.fixture
def vi_current():
    return VersionInfo(latest_version="1.0.0", is_outdated=False)


@pytest.fixture
def vr_vuln():
    return VulnerabilityReport(
        vulnerabilities=[{"id": "CVE-2024-1234", "severity": "HIGH"}],
        is_vulnerable=True,
    )


@pytest.fixture
def vr_clean():
    return VulnerabilityReport(vulnerabilities=[], is_vulnerable=False)


def test_build_advice_outdated_only(dep, vi_outdated, vr_clean):
    advice = build_advice(dep, vi_outdated, vr_clean)
    assert advice is not None
    assert advice.suggested_version == "2.0.0"
    assert advice.has_action is True
    assert len(advice.reasons) == 1
    assert "Outdated" in advice.reasons[0]


def test_build_advice_vuln_only(dep, vi_current, vr_vuln):
    advice = build_advice(dep, vi_current, vr_vuln)
    assert advice is not None
    assert "CVE-2024-1234" in advice.vuln_ids
    assert any("vulnerability" in r for r in advice.reasons)


def test_build_advice_clean_returns_none(dep, vi_current, vr_clean):
    advice = build_advice(dep, vi_current, vr_clean)
    assert advice is None


def test_build_advice_no_version_info(dep, vr_vuln):
    advice = build_advice(dep, None, vr_vuln)
    assert advice is not None
    assert advice.suggested_version is None
    assert advice.has_action is False


def test_build_remediation_plan_skips_missing_dep(vi_outdated, vr_clean):
    rows = [{"version_info": vi_outdated, "vulnerability_report": vr_clean}]
    plan = build_remediation_plan(rows)
    assert plan == []


def test_build_remediation_plan_full(dep, vi_outdated, vr_vuln):
    rows = [
        {"dependency": dep, "version_info": vi_outdated, "vulnerability_report": vr_vuln}
    ]
    plan = build_remediation_plan(rows)
    assert len(plan) == 1
    assert plan[0].suggested_version == "2.0.0"


def test_run_remediation_file_not_found():
    main_parser = argparse.ArgumentParser()
    subs = main_parser.add_subparsers()
    build_remediation_parser(subs)
    args = main_parser.parse_args(["remediation", "nonexistent_file.txt"])
    code = run_remediation(args)
    assert code == 2


def test_run_remediation_returns_zero_when_clean(dep, vi_current, vr_clean, tmp_path):
    tree_file = tmp_path / "deps.txt"
    tree_file.write_text("+--- org.example:lib:1.0.0\n")
    row = {
        "dependency": dep,
        "version_info": vi_current,
        "vulnerability_report": vr_clean,
    }
    with patch("gradle_dep_audit.remediation_cmd.run_audit_from_file", return_value=[row]):
        main_parser = argparse.ArgumentParser()
        subs = main_parser.add_subparsers()
        build_remediation_parser(subs)
        args = main_parser.parse_args(["remediation", str(tree_file)])
        code = run_remediation(args)
    assert code == 0


def test_run_remediation_json_format(dep, vi_outdated, vr_clean, tmp_path, capsys):
    tree_file = tmp_path / "deps.txt"
    tree_file.write_text("+--- org.example:lib:1.0.0\n")
    row = {
        "dependency": dep,
        "version_info": vi_outdated,
        "vulnerability_report": vr_clean,
    }
    with patch("gradle_dep_audit.remediation_cmd.run_audit_from_file", return_value=[row]):
        main_parser = argparse.ArgumentParser()
        subs = main_parser.add_subparsers()
        build_remediation_parser(subs)
        args = main_parser.parse_args(["remediation", str(tree_file), "--format", "json"])
        code = run_remediation(args)
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    assert len(data) == 1
    assert data[0]["suggested_version"] == "2.0.0"
    assert code == 1
