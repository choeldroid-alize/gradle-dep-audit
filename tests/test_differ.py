"""Tests for gradle_dep_audit.differ."""

import pytest

from gradle_dep_audit.differ import diff_results, DiffResult
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo


def _dep(group: str, artifact: str, version: str) -> Dependency:
    return Dependency(group=group, artifact=artifact, version=version)


def _row(dep: Dependency, vulns=None, latest: str | None = None) -> dict:
    vr = VulnerabilityReport(
        purl=f"pkg:maven/{dep.group}/{dep.artifact}@{dep.version}",
        vulnerabilities=vulns or [],
    )
    vi = VersionInfo(current=dep.version, latest=latest or dep.version, is_outdated=False)
    return {"dependency": dep, "vulnerability_report": vr, "version_info": vi}


@pytest.fixture
def dep_a():
    return _dep("com.example", "alpha", "1.0.0")


@pytest.fixture
def dep_b():
    return _dep("com.example", "beta", "2.0.0")


def test_diff_no_changes(dep_a, dep_b):
    rows = [_row(dep_a), _row(dep_b)]
    result = diff_results(rows, rows)
    assert result.added == []
    assert result.removed == []
    assert result.upgraded == []
    assert result.newly_vulnerable == []
    assert result.resolved_vulnerabilities == []


def test_diff_added_dependency(dep_a, dep_b):
    before = [_row(dep_a)]
    after = [_row(dep_a), _row(dep_b)]
    result = diff_results(before, after)
    assert len(result.added) == 1
    assert result.added[0]["dependency"].artifact == "beta"
    assert result.removed == []


def test_diff_removed_dependency(dep_a, dep_b):
    before = [_row(dep_a), _row(dep_b)]
    after = [_row(dep_a)]
    result = diff_results(before, after)
    assert len(result.removed) == 1
    assert result.removed[0]["dependency"].artifact == "beta"


def test_diff_upgraded_dependency(dep_a):
    old_dep = _dep("com.example", "alpha", "1.0.0")
    new_dep = _dep("com.example", "alpha", "1.1.0")
    before = [_row(old_dep)]
    after = [_row(new_dep)]
    result = diff_results(before, after)
    assert len(result.upgraded) == 1
    old_row, new_row = result.upgraded[0]
    assert old_row["dependency"].version == "1.0.0"
    assert new_row["dependency"].version == "1.1.0"


def test_diff_newly_vulnerable(dep_a):
    before = [_row(dep_a, vulns=[])]
    after = [_row(dep_a, vulns=[{"id": "CVE-2024-1234", "severity": "HIGH"}])]
    result = diff_results(before, after)
    assert len(result.newly_vulnerable) == 1


def test_diff_resolved_vulnerability(dep_a):
    before = [_row(dep_a, vulns=[{"id": "CVE-2024-1234", "severity": "HIGH"}])]
    after = [_row(dep_a, vulns=[])]
    result = diff_results(before, after)
    assert len(result.resolved_vulnerabilities) == 1


def test_diff_repr():
    dr = DiffResult(added=[{}], removed=[], upgraded=[], newly_vulnerable=[], resolved_vulnerabilities=[])
    assert "DiffResult" in repr(dr)


def test_diff_empty_inputs():
    result = diff_results([], [])
    assert result.added == []
    assert result.removed == []
