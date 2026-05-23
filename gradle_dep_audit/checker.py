"""Check dependencies against known vulnerability sources."""

import requests
from dataclasses import dataclass
from typing import Optional
from .parser import Dependency

OSSINDEX_URL = "https://ossindex.sonatype.org/api/v3/component-report"


@dataclass
class VulnerabilityReport:
    dependency: Dependency
    vulnerabilities: list[dict]
    latest_version: Optional[str] = None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0


def _build_purl(dep: Dependency) -> str:
    return f"pkg:maven/{dep.group}/{dep.artifact}@{dep.version}"


def check_vulnerabilities(
    dependencies: list[Dependency],
    token: Optional[str] = None,
    timeout: int = 10,
) -> list[VulnerabilityReport]:
    """Query OSS Index for vulnerability data on a list of dependencies."""
    if not dependencies:
        return []

    purls = [_build_purl(d) for d in dependencies]
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.post(
            OSSINDEX_URL,
            json={"coordinates": purls},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        results = response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to contact OSS Index: {exc}") from exc

    dep_map = {_build_purl(d): d for d in dependencies}
    reports = []
    for item in results:
        purl = item.get("coordinates", "")
        dep = dep_map.get(purl)
        if dep:
            reports.append(VulnerabilityReport(
                dependency=dep,
                vulnerabilities=item.get("vulnerabilities", []),
            ))
    return reports
