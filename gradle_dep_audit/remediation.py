"""Remediation advisor: suggests upgrade actions for outdated/vulnerable deps."""

from dataclasses import dataclass, field
from typing import List, Optional

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo
from gradle_dep_audit.checker import VulnerabilityReport


@dataclass
class RemediationAdvice:
    dependency: Dependency
    current_version: str
    suggested_version: Optional[str]
    reasons: List[str] = field(default_factory=list)
    vuln_ids: List[str] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"RemediationAdvice({self.dependency.coordinate()} "
            f"{self.current_version} -> {self.suggested_version})"
        )

    @property
    def has_action(self) -> bool:
        return self.suggested_version is not None and (
            self.suggested_version != self.current_version
        )


def build_advice(
    dep: Dependency,
    version_info: Optional[VersionInfo],
    vuln_report: Optional[VulnerabilityReport],
) -> Optional[RemediationAdvice]:
    """Return a RemediationAdvice for *dep*, or None if no action is needed."""
    reasons: List[str] = []
    vuln_ids: List[str] = []
    suggested: Optional[str] = None

    if version_info and version_info.is_outdated and version_info.latest_version:
        reasons.append(
            f"Outdated: {dep.version} -> {version_info.latest_version}"
        )
        suggested = version_info.latest_version

    if vuln_report and vuln_report.vulnerabilities:
        for v in vuln_report.vulnerabilities:
            vid = v.get("id", "UNKNOWN")
            vuln_ids.append(vid)
        reasons.append(
            f"{len(vuln_ids)} known vulnerability/vulnerabilities found"
        )
        # Prefer the latest version as the fix target when available
        if suggested is None and version_info and version_info.latest_version:
            suggested = version_info.latest_version

    if not reasons:
        return None

    return RemediationAdvice(
        dependency=dep,
        current_version=dep.version,
        suggested_version=suggested,
        reasons=reasons,
        vuln_ids=vuln_ids,
    )


def build_remediation_plan(
    rows: List[dict],
) -> List[RemediationAdvice]:
    """Build a remediation plan from a list of audit result rows."""
    plan: List[RemediationAdvice] = []
    for row in rows:
        dep = row.get("dependency")
        if dep is None:
            continue
        advice = build_advice(
            dep=dep,
            version_info=row.get("version_info"),
            vuln_report=row.get("vulnerability_report"),
        )
        if advice is not None:
            plan.append(advice)
    return plan
