"""Tests for gradle_dep_audit.suppression."""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from gradle_dep_audit.suppression import (
    apply_suppressions,
    is_suppressed,
    load_suppression,
    save_suppression,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dep(group="com.example", artifact="lib", version="1.0"):
    return SimpleNamespace(group=group, artifact=artifact, version=version)


def _row(dep, vuln_ids=()):
    vulns = [{"id": vid, "severity": "HIGH"} for vid in vuln_ids]
    vr = SimpleNamespace(vulnerabilities=vulns)
    return {"dependency": dep, "vulnerability_report": vr}


_COORD = "com.example:lib:1.0"
_FUTURE = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
_PAST = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# is_suppressed
# ---------------------------------------------------------------------------

def test_is_suppressed_exact_match():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001"}]
    row = _row(_dep())
    assert is_suppressed(sups, row, "CVE-2024-001") is True


def test_is_suppressed_no_match():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001"}]
    row = _row(_dep())
    assert is_suppressed(sups, row, "CVE-2024-999") is False


def test_is_suppressed_wildcard_vuln():
    sups = [{"coordinate": _COORD, "vuln_id": "*"}]
    row = _row(_dep())
    assert is_suppressed(sups, row, "CVE-anything") is True


def test_is_suppressed_future_expiry_still_active():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001", "expires": _FUTURE}]
    row = _row(_dep())
    assert is_suppressed(sups, row, "CVE-2024-001") is True


def test_is_suppressed_past_expiry_inactive():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001", "expires": _PAST}]
    row = _row(_dep())
    assert is_suppressed(sups, row, "CVE-2024-001") is False


def test_is_suppressed_missing_dependency_key():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001"}]
    assert is_suppressed(sups, {}, "CVE-2024-001") is False


# ---------------------------------------------------------------------------
# apply_suppressions
# ---------------------------------------------------------------------------

def test_apply_suppressions_removes_matching_vuln():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001"}]
    rows = [_row(_dep(), vuln_ids=["CVE-2024-001", "CVE-2024-002"])]
    result = apply_suppressions(sups, rows)
    ids = [v["id"] for v in result[0]["vulnerability_report"].vulnerabilities]
    assert ids == ["CVE-2024-002"]


def test_apply_suppressions_does_not_mutate_original():
    sups = [{"coordinate": _COORD, "vuln_id": "CVE-2024-001"}]
    rows = [_row(_dep(), vuln_ids=["CVE-2024-001"])]
    apply_suppressions(sups, rows)
    assert len(rows[0]["vulnerability_report"].vulnerabilities) == 1


def test_apply_suppressions_empty_list():
    result = apply_suppressions([], [])
    assert result == []


# ---------------------------------------------------------------------------
# save / load round-trip
# ---------------------------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "sups.json")
    entries = [{"coordinate": _COORD, "vuln_id": "CVE-1", "reason": "test"}]
    save_suppression(path, entries)
    loaded = load_suppression(path)
    assert loaded == entries


def test_load_returns_empty_for_missing_file(tmp_path):
    path = str(tmp_path / "nonexistent.json")
    assert load_suppression(path) == []
