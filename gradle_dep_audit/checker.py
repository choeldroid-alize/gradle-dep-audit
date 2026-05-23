"""Check dependencies against OSS Index for known vulnerabilities."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

import requests

from .cache import VulnerabilityCache
from .parser import Dependency

OSS_INDEX_URL = "https://ossindex.sonatype.org/api/v3/component-report"
_DEFAULT_CACHE = VulnerabilityCache()


@dataclass
class VulnerabilityReport:
    dependency: Dependency
    vulnerabilities: List[dict] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0


def is_vulnerable(report: VulnerabilityReport) -> bool:
    return report.is_vulnerable


def _build_purl(dep: Dependency) -> str:
    return f"pkg:maven/{dep.group}/{dep.artifact}@{dep.version}"


def _fetch_report(purl: str, cache: VulnerabilityCache, timeout: int) -> dict:
    """Return OSS Index response for purl, using cache when available."""
    cached = cache.get(purl)
    if cached is not None:
        return cached

    username = os.environ.get("OSS_INDEX_USER", "")
    token = os.environ.get("OSS_INDEX_TOKEN", "")
    auth = (username, token) if username and token else None

    response = requests.post(
        OSS_INDEX_URL,
        json={"coordinates": [purl]},
        auth=auth,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    payload = data[0] if data else {}
    cache.set(purl, payload)
    return payload


def check_vulnerabilities(
    deps: List[Dependency],
    cache: Optional[VulnerabilityCache] = None,
    timeout: int = 10,
) -> List[VulnerabilityReport]:
    """Query OSS Index for each dependency and return vulnerability reports."""
    if cache is None:
        cache = _DEFAULT_CACHE

    reports: List[VulnerabilityReport] = []
    for dep in deps:
        purl = _build_purl(dep)
        try:
            payload = _fetch_report(purl, cache, timeout)
            vulns = payload.get("vulnerabilities", [])
        except Exception:  # noqa: BLE001
            vulns = []
        reports.append(VulnerabilityReport(dependency=dep, vulnerabilities=vulns))
    return reports
