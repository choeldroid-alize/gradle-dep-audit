"""Tests for trend analysis and trend printer."""

from __future__ import annotations

import io
import json
from unittest.mock import patch

import pytest

from gradle_dep_audit.trend import TrendPoint, TrendReport, _point_from_rows, build_trend
from gradle_dep_audit.trend_printer import print_trend_text, print_trend_json


# ---------------------------------------------------------------------------
# _point_from_rows
# ---------------------------------------------------------------------------

def _make_row(outdated=False, vulns=None):
    return {"is_outdated": outdated, "vulnerabilities": vulns or []}


def test_point_from_rows_counts_correctly():
    rows = [
        _make_row(outdated=True, vulns=[{"severity": "CRITICAL"}]),
        _make_row(outdated=True, vulns=[{"severity": "HIGH"}]),
        _make_row(outdated=False, vulns=[]),
    ]
    p = _point_from_rows("snap1", rows)
    assert p.total == 3
    assert p.outdated == 2
    assert p.vulnerable == 2
    assert p.critical == 1
    assert p.high == 1


def test_point_from_rows_empty():
    p = _point_from_rows("empty", [])
    assert p.total == 0
    assert p.vulnerable == 0


# ---------------------------------------------------------------------------
# TrendReport properties
# ---------------------------------------------------------------------------

def test_trend_report_improving():
    report = TrendReport(points=[
        TrendPoint("a", 10, 5, 4, 1, 1),
        TrendPoint("b", 10, 3, 2, 0, 1),
    ])
    assert report.improving is True
    assert report.delta_vulnerable == -2


def test_trend_report_worsening():
    report = TrendReport(points=[
        TrendPoint("a", 10, 1, 1, 0, 0),
        TrendPoint("b", 10, 3, 5, 2, 1),
    ])
    assert report.improving is False
    assert report.delta_vulnerable == 4


def test_trend_report_single_point_returns_none():
    report = TrendReport(points=[TrendPoint("a", 5, 1, 1, 0, 0)])
    assert report.improving is None
    assert report.delta_vulnerable == 0


# ---------------------------------------------------------------------------
# build_trend
# ---------------------------------------------------------------------------

def test_build_trend_calls_load_snapshot():
    rows_a = [_make_row(outdated=True, vulns=[{"severity": "HIGH"}])]
    rows_b = [_make_row(outdated=False, vulns=[])]

    with patch("gradle_dep_audit.trend.load_snapshot", side_effect=[rows_a, rows_b]) as mock_load:
        report = build_trend(["snap-1", "snap-2"], snapshots_dir="/tmp")

    assert mock_load.call_count == 2
    assert len(report.points) == 2
    assert report.points[0].vulnerable == 1
    assert report.points[1].vulnerable == 0


# ---------------------------------------------------------------------------
# print_trend_text
# ---------------------------------------------------------------------------

def test_print_trend_text_no_points():
    out = io.StringIO()
    print_trend_text(TrendReport(), out=out)
    assert "No trend data" in out.getvalue()


def test_print_trend_text_contains_labels():
    report = TrendReport(points=[
        TrendPoint("v1.0", 10, 2, 3, 1, 1),
        TrendPoint("v2.0", 10, 1, 1, 0, 0),
    ])
    out = io.StringIO()
    print_trend_text(report, out=out)
    text = out.getvalue()
    assert "v1.0" in text
    assert "v2.0" in text
    assert "improved" in text


# ---------------------------------------------------------------------------
# print_trend_json
# ---------------------------------------------------------------------------

def test_print_trend_json_structure():
    report = TrendReport(points=[
        TrendPoint("snap-a", 5, 2, 1, 0, 1),
    ])
    out = io.StringIO()
    print_trend_json(report, out=out)
    data = json.loads(out.getvalue())
    assert "points" in data
    assert data["points"][0]["label"] == "snap-a"
    assert data["delta_vulnerable"] == 0
