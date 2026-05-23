"""Tests for gradle_dep_audit.pipeline."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gradle_dep_audit.pipeline import run_audit, run_audit_from_file
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport


SAMPLE_TREE = """
+--- com.example:alpha:1.0.0
\\--- org.sample:beta:2.3.0
"""


@pytest.fixture(autouse=True)
def _mock_network(monkeypatch):
    """Prevent real network calls in every test."""
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._resolve",
        lambda dep: VersionInfo(latest_version="9.9.9", outdated=True),
    )
    monkeypatch.setattr(
        "gradle_dep_audit.pipeline._check",
        lambda dep: VulnerabilityReport(purl="", vulnerabilities=[]),
    )


def test_run_audit_returns_correct_count():
    rows = run_audit(SAMPLE_TREE)
    assert len(rows) == 2


def test_run_audit_row_structure():
    rows = run_audit(SAMPLE_TREE)
    dep, vi, vr = rows[0]
    assert isinstance(dep, Dependency)
    assert isinstance(vi, VersionInfo)
    assert isinstance(vr, VulnerabilityReport)


def test_run_audit_skip_vuln_returns_empty_vulns():
    rows = run_audit(SAMPLE_TREE, skip_vuln=True)
    for _, _, vr in rows:
        assert vr.vulnerabilities == []


def test_run_audit_skip_outdated_returns_no_outdated():
    rows = run_audit(SAMPLE_TREE, skip_outdated=True)
    for _, vi, _ in rows:
        assert vi.outdated is False


def test_run_audit_from_file(tmp_path: Path):
    tree_file = tmp_path / "deps.txt"
    tree_file.write_text(SAMPLE_TREE, encoding="utf-8")
    result = run_audit_from_file(tree_file, output_format="csv")
    assert "coordinate" in result
    assert "com.example:alpha:1.0.0" in result


def test_run_audit_from_file_json(tmp_path: Path):
    import json

    tree_file = tmp_path / "deps.txt"
    tree_file.write_text(SAMPLE_TREE, encoding="utf-8")
    result = run_audit_from_file(tree_file, output_format="json")
    data = json.loads(result)
    assert len(data) == 2
