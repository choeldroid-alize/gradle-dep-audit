"""Tests for gradle_dep_audit.baseline."""

import json
import os
import pytest

from gradle_dep_audit.baseline import (
    _row_key,
    save_baseline,
    load_baseline,
    filter_new_issues,
    apply_baseline,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row(dep: str, vuln_ids=None):
    return {"dependency": dep, "vuln_ids": vuln_ids or []}


# ---------------------------------------------------------------------------
# _row_key
# ---------------------------------------------------------------------------

def test_row_key_stable_ordering():
    r = _row("com.example:lib:1.0", ["CVE-2023-9999", "CVE-2022-0001"])
    assert _row_key(r) == "com.example:lib:1.0|CVE-2022-0001|CVE-2023-9999"


def test_row_key_no_vulns():
    assert _row_key(_row("org.foo:bar:2.0")) == "org.foo:bar:2.0|"


# ---------------------------------------------------------------------------
# save / load round-trip
# ---------------------------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    baseline_file = str(tmp_path / "baseline.json")
    rows = [
        _row("com.example:a:1.0", ["CVE-2024-0001"]),
        _row("com.example:b:2.0"),  # no vulns — should be excluded
    ]
    save_baseline(rows, path=baseline_file)

    keys = load_baseline(path=baseline_file)
    assert keys is not None
    assert len(keys) == 1
    assert "com.example:a:1.0|CVE-2024-0001" in keys


def test_load_baseline_missing_file(tmp_path):
    result = load_baseline(path=str(tmp_path / "nonexistent.json"))
    assert result is None


def test_save_baseline_creates_valid_json(tmp_path):
    baseline_file = str(tmp_path / "b.json")
    save_baseline([_row("g:a:1", ["CVE-1"])], path=baseline_file)
    data = json.loads(open(baseline_file).read())
    assert isinstance(data, list)
    assert data[0]["dependency"] == "g:a:1"


# ---------------------------------------------------------------------------
# filter_new_issues
# ---------------------------------------------------------------------------

def test_filter_new_issues_removes_known():
    known = {"g:a:1|CVE-1"}
    rows = [
        _row("g:a:1", ["CVE-1"]),
        _row("g:b:2", ["CVE-2"]),
    ]
    result = filter_new_issues(rows, known)
    assert len(result) == 1
    assert result[0]["dependency"] == "g:b:2"


def test_filter_new_issues_empty_baseline():
    rows = [_row("g:a:1", ["CVE-1"])]
    assert filter_new_issues(rows, set()) == rows


# ---------------------------------------------------------------------------
# apply_baseline integration
# ---------------------------------------------------------------------------

def test_apply_baseline_no_file_returns_all(tmp_path):
    rows = [_row("g:a:1", ["CVE-1"]), _row("g:b:2")]
    result = apply_baseline(rows, baseline_path=str(tmp_path / "missing.json"))
    assert result == rows


def test_apply_baseline_filters_known_issues(tmp_path):
    baseline_file = str(tmp_path / "bl.json")
    existing = [_row("g:a:1", ["CVE-1"])]
    save_baseline(existing, path=baseline_file)

    new_rows = [
        _row("g:a:1", ["CVE-1"]),  # known
        _row("g:c:3", ["CVE-3"]),  # new
    ]
    result = apply_baseline(new_rows, baseline_path=baseline_file)
    assert len(result) == 1
    assert result[0]["dependency"] == "g:c:3"
