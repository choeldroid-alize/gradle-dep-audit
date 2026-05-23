"""Formatting utilities for dependency and vulnerability output."""

from __future__ import annotations

from typing import List, Tuple

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo


COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"


def _colorize(text: str, color: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{color}{text}{COLOR_RESET}"


def format_dependency_row(
    dep: Dependency,
    version_info: VersionInfo | None,
    vuln_report: VulnerabilityReport | None,
    use_color: bool = True,
) -> str:
    """Return a single formatted row describing a dependency's status."""
    coord = dep.coordinate()
    parts = [coord]

    if version_info and version_info.latest_version:
        if version_info.is_outdated:
            label = _colorize(
                f"outdated (latest: {version_info.latest_version})",
                COLOR_YELLOW,
                use_color,
            )
        else:
            label = _colorize("up-to-date", COLOR_GREEN, use_color)
        parts.append(label)

    if vuln_report and vuln_report.vulnerabilities:
        count = len(vuln_report.vulnerabilities)
        vuln_label = _colorize(f"{count} vuln(s)", COLOR_RED, use_color)
        parts.append(vuln_label)

    return "  ".join(parts)


def format_summary(
    results: List[Tuple[Dependency, VersionInfo | None, VulnerabilityReport | None]],
    use_color: bool = True,
) -> str:
    """Return a human-readable summary block for a list of dependency results."""
    lines: List[str] = []
    outdated_count = 0
    vulnerable_count = 0

    for dep, vi, vr in results:
        lines.append(format_dependency_row(dep, vi, vr, use_color=use_color))
        if vi and vi.is_outdated:
            outdated_count += 1
        if vr and vr.vulnerabilities:
            vulnerable_count += 1

    total = len(results)
    summary_line = (
        f"\nScanned {total} dependencies: "
        f"{_colorize(str(outdated_count) + ' outdated', COLOR_YELLOW, use_color)}, "
        f"{_colorize(str(vulnerable_count) + ' vulnerable', COLOR_RED, use_color)}"
    )
    lines.append(summary_line)
    return "\n".join(lines)
