"""Orchestrate the full audit pipeline: parse → resolve → check → export."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from gradle_dep_audit.checker import VulnerabilityReport, is_vulnerable
from gradle_dep_audit.exporter import AuditRow, export
from gradle_dep_audit.parser import Dependency, parse_dependency_tree
from gradle_dep_audit.resolver import VersionInfo, check_version


def _resolve(dep: Dependency) -> VersionInfo:
    """Fetch version info, returning a safe fallback on error."""
    try:
        return check_version(dep)
    except Exception:  # noqa: BLE001
        return VersionInfo(latest_version=None, outdated=False)


def _check(dep: Dependency) -> Optional[VulnerabilityReport]:
    """Fetch vulnerability report, returning *None* on error."""
    try:
        return is_vulnerable(dep)
    except Exception:  # noqa: BLE001
        return None


def run_audit(
    tree_text: str,
    *,
    skip_vuln: bool = False,
    skip_outdated: bool = False,
) -> List[AuditRow]:
    """Run the full audit pipeline on *tree_text* and return a list of AuditRow."""
    deps: List[Dependency] = parse_dependency_tree(tree_text)
    rows: List[AuditRow] = []
    for dep in deps:
        vi = _resolve(dep) if not skip_outdated else VersionInfo(latest_version=None, outdated=False)
        vr = _check(dep) if not skip_vuln else VulnerabilityReport(purl="", vulnerabilities=[])
        rows.append((dep, vi, vr))
    return rows


def run_audit_from_file(
    path: Path,
    *,
    skip_vuln: bool = False,
    skip_outdated: bool = False,
    output_format: str = "json",
) -> str:
    """Read a Gradle dependency tree file and return the formatted audit result."""
    tree_text = path.read_text(encoding="utf-8")
    rows = run_audit(tree_text, skip_vuln=skip_vuln, skip_outdated=skip_outdated)
    return export(rows, output_format)
