"""Tests for gradle_dep_audit.notifier."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from gradle_dep_audit.differ import DiffResult
from gradle_dep_audit.notifier import (
    NotificationPayload,
    build_payload,
    send_slack,
)
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dep(group: str, artifact: str, version: str = "1.0.0") -> Dependency:
    return Dependency(group=group, artifact=artifact, version=version)


def _row(dep: Dependency, vulns=None, outdated: bool = False) -> dict:
    vi = VersionInfo(
        current=dep.version,
        latest="2.0.0" if outdated else dep.version,
        is_outdated=outdated,
    )
    return {
        "dependency": dep,
        "version_info": vi,
        "vulnerabilities": vulns or [],
    }


# ---------------------------------------------------------------------------
# NotificationPayload
# ---------------------------------------------------------------------------

def test_payload_is_empty_when_no_issues():
    p = NotificationPayload(new_vulnerable=0, new_outdated=0, fixed=0)
    assert p.is_empty() is True


def test_payload_not_empty_with_vulns():
    p = NotificationPayload(new_vulnerable=1, new_outdated=0, fixed=0)
    assert p.is_empty() is False


def test_payload_to_dict_keys():
    p = NotificationPayload(new_vulnerable=2, new_outdated=1, fixed=3, details=["x"])
    d = p.to_dict()
    assert set(d.keys()) == {"new_vulnerable", "new_outdated", "fixed", "details"}
    assert d["new_vulnerable"] == 2


# ---------------------------------------------------------------------------
# build_payload
# ---------------------------------------------------------------------------

def test_build_payload_counts_new_vulnerabilities():
    dep = _dep("org.example", "lib", "1.0")
    added_row = _row(dep, vulns=[{"id": "CVE-2024-001", "severity": "HIGH"}])
    diff = DiffResult(added=[added_row], removed=[], changed=[])
    payload = build_payload(diff)
    assert payload.new_vulnerable == 1
    assert any("CVE-2024-001" in d for d in payload.details)


def test_build_payload_counts_new_outdated():
    dep = _dep("com.example", "core", "1.0")
    added_row = _row(dep, outdated=True)
    diff = DiffResult(added=[added_row], removed=[], changed=[])
    payload = build_payload(diff)
    assert payload.new_outdated == 1


def test_build_payload_counts_fixed():
    dep = _dep("com.example", "old", "0.9")
    removed_row = _row(dep, vulns=[{"id": "CVE-OLD", "severity": "LOW"}])
    diff = DiffResult(added=[], removed=[removed_row], changed=[])
    payload = build_payload(diff)
    assert payload.fixed == 1
    assert payload.is_empty() is True  # no *new* issues


def test_build_payload_empty_diff():
    diff = DiffResult(added=[], removed=[], changed=[])
    payload = build_payload(diff)
    assert payload.is_empty() is True
    assert payload.fixed == 0


# ---------------------------------------------------------------------------
# send_slack
# ---------------------------------------------------------------------------

def test_send_slack_skips_when_empty():
    payload = NotificationPayload(new_vulnerable=0, new_outdated=0, fixed=0)
    with patch("urllib.request.urlopen") as mock_open:
        result = send_slack(payload, "https://hooks.slack.com/fake")
    assert result is True
    mock_open.assert_not_called()


def test_send_slack_posts_json_body():
    payload = NotificationPayload(
        new_vulnerable=1, new_outdated=0, fixed=0, details=["NEW VULN lib: CVE-X"]
    )
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_ctx) as mock_open:
        result = send_slack(payload, "https://hooks.slack.com/fake")
    assert result is True
    call_args = mock_open.call_args
    request_obj = call_args[0][0]
    body = json.loads(request_obj.data.decode())
    assert "text" in body
    assert "CVE-X" in body["text"]


def test_send_slack_returns_false_on_network_error():
    import urllib.error
    payload = NotificationPayload(new_vulnerable=1, new_outdated=0, fixed=0)
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        result = send_slack(payload, "https://hooks.slack.com/fake")
    assert result is False
