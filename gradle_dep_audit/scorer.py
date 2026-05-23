"""Risk scoring module: computes a composite risk score for each audited dependency."""

from dataclasses import dataclass
from typing import Optional

from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo

# Weight constants
_VULN_CRITICAL_WEIGHT = 10
_VULN_HIGH_WEIGHT = 7
_VULN_MEDIUM_WEIGHT = 4
_VULN_LOW_WEIGHT = 1
_OUTDATED_WEIGHT = 3
_MAJOR_OUTDATED_BONUS = 4  # extra points when major version is behind


@dataclass
class RiskScore:
    score: int
    reasons: list

    def __repr__(self) -> str:  # pragma: no cover
        return f"RiskScore(score={self.score}, reasons={self.reasons})"

    @property
    def label(self) -> str:
        if self.score >= 10:
            return "CRITICAL"
        if self.score >= 7:
            return "HIGH"
        if self.score >= 4:
            return "MEDIUM"
        if self.score >= 1:
            return "LOW"
        return "NONE"


def compute_score(
    version_info: Optional[VersionInfo],
    vuln_report: Optional[VulnerabilityReport],
) -> RiskScore:
    """Return a RiskScore for a dependency given its version and vulnerability data."""
    score = 0
    reasons = []

    if vuln_report and vuln_report.vulnerabilities:
        for vuln in vuln_report.vulnerabilities:
            sev = (vuln.get("severity") or "").upper()
            if sev == "CRITICAL":
                score += _VULN_CRITICAL_WEIGHT
                reasons.append(f"Critical vulnerability: {vuln.get('id', 'unknown')}")
            elif sev == "HIGH":
                score += _VULN_HIGH_WEIGHT
                reasons.append(f"High vulnerability: {vuln.get('id', 'unknown')}")
            elif sev == "MEDIUM":
                score += _VULN_MEDIUM_WEIGHT
                reasons.append(f"Medium vulnerability: {vuln.get('id', 'unknown')}")
            else:
                score += _VULN_LOW_WEIGHT
                reasons.append(f"Low vulnerability: {vuln.get('id', 'unknown')}")

    if version_info and version_info.is_outdated:
        score += _OUTDATED_WEIGHT
        reasons.append(
            f"Outdated: {version_info.current} -> {version_info.latest}"
        )
        try:
            cur_major = int(str(version_info.current).split(".")[0])
            lat_major = int(str(version_info.latest).split(".")[0])
            if lat_major > cur_major:
                score += _MAJOR_OUTDATED_BONUS
                reasons.append("Major version behind")
        except (ValueError, IndexError, AttributeError):
            pass

    return RiskScore(score=score, reasons=reasons)
