"""Tests for gradle_dep_audit.resolver."""

from unittest.mock import MagicMock, patch

import pytest

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import (
    VersionInfo,
    _is_outdated,
    check_version,
    fetch_latest_version,
)


@pytest.fixture()
def sample_dep() -> Dependency:
    return Dependency(group="com.google.guava", artifact="guava", version="31.0-jre")


# ---------------------------------------------------------------------------
# _is_outdated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "current, latest, expected",
    [
        ("1.0.0", "1.0.0", False),
        ("1.0.0", "1.0.1", True),
        ("2.3.0", "2.2.9", False),
        ("1.0", "1.0.0", False),
        ("1.0", "1.1", True),
        ("v1.2.3", "v1.2.4", True),
    ],
)
def test_is_outdated(current: str, latest: str, expected: bool) -> None:
    assert _is_outdated(current, latest) is expected


# ---------------------------------------------------------------------------
# fetch_latest_version
# ---------------------------------------------------------------------------


def test_fetch_latest_version_success(sample_dep: Dependency) -> None:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": {"docs": [{"v": "33.0-jre"}]}}
    mock_resp.raise_for_status = MagicMock()

    with patch("gradle_dep_audit.resolver._SESSION.get", return_value=mock_resp):
        result = fetch_latest_version(sample_dep)

    assert result == "33.0-jre"


def test_fetch_latest_version_empty_docs(sample_dep: Dependency) -> None:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": {"docs": []}}
    mock_resp.raise_for_status = MagicMock()

    with patch("gradle_dep_audit.resolver._SESSION.get", return_value=mock_resp):
        result = fetch_latest_version(sample_dep)

    assert result is None


def test_fetch_latest_version_network_error(sample_dep: Dependency) -> None:
    import requests

    with patch(
        "gradle_dep_audit.resolver._SESSION.get",
        side_effect=requests.ConnectionError("unreachable"),
    ):
        result = fetch_latest_version(sample_dep)

    assert result is None


# ---------------------------------------------------------------------------
# check_version
# ---------------------------------------------------------------------------


def test_check_version_outdated(sample_dep: Dependency) -> None:
    info = check_version(sample_dep, latest="33.0-jre")
    assert isinstance(info, VersionInfo)
    assert info.outdated is True
    assert info.latest == "33.0-jre"


def test_check_version_up_to_date(sample_dep: Dependency) -> None:
    info = check_version(sample_dep, latest="31.0-jre")
    assert info.outdated is False


def test_check_version_fetches_when_latest_not_provided(sample_dep: Dependency) -> None:
    with patch(
        "gradle_dep_audit.resolver.fetch_latest_version", return_value="32.0-jre"
    ) as mock_fetch:
        info = check_version(sample_dep)

    mock_fetch.assert_called_once_with(sample_dep)
    assert info.outdated is True


def test_check_version_treats_none_latest_as_up_to_date(sample_dep: Dependency) -> None:
    with patch("gradle_dep_audit.resolver.fetch_latest_version", return_value=None):
        info = check_version(sample_dep)

    assert info.outdated is False
    assert info.latest == sample_dep.version
