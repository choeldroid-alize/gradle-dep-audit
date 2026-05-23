"""Resolve latest versions of dependencies from Maven Central."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import requests

from .parser import Dependency

logger = logging.getLogger(__name__)

MAVEN_SEARCH_URL = "https://search.maven.org/solrsearch/select"
_SESSION = requests.Session()


@dataclass
class VersionInfo:
    current: str
    latest: str
    outdated: bool

    def __repr__(self) -> str:  # pragma: no cover
        status = "outdated" if self.outdated else "up-to-date"
        return f"VersionInfo({self.current!r} -> {self.latest!r}, {status})"


def fetch_latest_version(dep: Dependency) -> Optional[str]:
    """Query Maven Central for the latest released version of *dep*.

    Returns the version string or ``None`` when the lookup fails.
    """
    params = {
        "q": f"g:{dep.group} AND a:{dep.artifact}",
        "rows": 1,
        "wt": "json",
        "core": "gav",
    }
    try:
        resp = _SESSION.get(MAVEN_SEARCH_URL, params=params, timeout=10)
        resp.raise_for_status()
        docs = resp.json().get("response", {}).get("docs", [])
        if docs:
            return docs[0].get("v")
    except requests.RequestException as exc:
        logger.warning("Version lookup failed for %s: %s", dep.coordinate(), exc)
    return None


def check_version(dep: Dependency, latest: Optional[str] = None) -> VersionInfo:
    """Return a :class:`VersionInfo` for *dep*, fetching latest if not supplied."""
    if latest is None:
        latest = fetch_latest_version(dep)
    if latest is None:
        # Cannot determine — treat as up-to-date to avoid false positives
        latest = dep.version
    outdated = _is_outdated(dep.version, latest)
    return VersionInfo(current=dep.version, latest=latest, outdated=outdated)


def _is_outdated(current: str, latest: str) -> bool:
    """Return True when *latest* is strictly newer than *current*."""
    if current == latest:
        return False
    try:
        cur_parts = [int(x) for x in current.lstrip("v").split(".")]
        lat_parts = [int(x) for x in latest.lstrip("v").split(".")]
        # Pad to equal length
        length = max(len(cur_parts), len(lat_parts))
        cur_parts += [0] * (length - len(cur_parts))
        lat_parts += [0] * (length - len(lat_parts))
        return lat_parts > cur_parts
    except ValueError:
        # Non-numeric versions — fall back to simple string comparison
        return latest > current
