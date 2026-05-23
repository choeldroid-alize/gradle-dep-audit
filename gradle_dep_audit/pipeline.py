"""Audit pipeline: resolve versions, check vulnerabilities, compute risk scores."""

from typing import List, Dict, Any, Optional

from gradle_dep_audit.parser import Dependency, parse_dependency_tree
from gradle_dep_audit.resolver import fetch_latest_version, check_version
from gradle_dep_audit.checker import VulnerabilityReport, is_vulnerable
from gradle_dep_audit.scorer import compute_score


def _resolve(dep: Dependency):
    """Fetch latest version info for a dependency."""
    latest = fetch_latest_version(dep)
    return check_version(dep, latest)


def _check(dep: Dependency) -> VulnerabilityReport:
    """Check a dependency for known vulnerabilities."""
    return is_vulnerable(dep)


def run_audit(
    deps: List[Dependency],
    skip_vuln: bool = False,
    skip_outdated: bool = False,
) -> List[Dict[str, Any]]:
    """Run the full audit pipeline over a list of dependencies.

    Returns a list of row dicts with keys:
      dependency, version_info, vuln_report, risk_score
    """
    rows = []
    for dep in deps:
        version_info = None if skip_outdated else _resolve(dep)
        vuln_report: Optional[VulnerabilityReport] = None if skip_vuln else _check(dep)
        risk_score = compute_score(version_info, vuln_report)
        rows.append(
            {
                "dependency": dep,
                "version_info": version_info,
                "vuln_report": vuln_report,
                "risk_score": risk_score,
            }
        )
    return rows


def run_audit_from_file(
    path: str,
    skip_vuln: bool = False,
    skip_outdated: bool = False,
) -> List[Dict[str, Any]]:
    """Parse a Gradle dependency tree file and run the audit pipeline."""
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    deps = parse_dependency_tree(content)
    return run_audit(deps, skip_vuln=skip_vuln, skip_outdated=skip_outdated)
