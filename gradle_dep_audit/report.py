"""Render vulnerability reports to stdout."""

import json
from typing import Literal
from .checker import VulnerabilityReport


def _severity_label(vuln: dict) -> str:
    score = vuln.get("cvssScore", 0.0)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def print_text_report(reports: list[VulnerabilityReport]) -> None:
    vulnerable = [r for r in reports if r.is_vulnerable]
    clean = len(reports) - len(vulnerable)

    print(f"Scanned {len(reports)} dependencies — "
          f"{len(vulnerable)} vulnerable, {clean} clean.\n")

    if not vulnerable:
        print("✓ No vulnerabilities found.")
        return

    for report in vulnerable:
        dep = report.dependency
        print(f"✗ {dep.coordinate}")
        for vuln in report.vulnerabilities:
            cve = vuln.get("cve") or vuln.get("id", "N/A")
            severity = _severity_label(vuln)
            title = vuln.get("title", "No title")
            print(f"    [{severity}] {cve}: {title}")
        print()


def print_json_report(reports: list[VulnerabilityReport]) -> None:
    output = []
    for r in reports:
        output.append({
            "coordinate": r.dependency.coordinate,
            "vulnerable": r.is_vulnerable,
            "vulnerabilities": r.vulnerabilities,
        })
    print(json.dumps(output, indent=2))


def print_report(
    reports: list[VulnerabilityReport],
    fmt: Literal["text", "json"] = "text",
) -> None:
    if fmt == "json":
        print_json_report(reports)
    else:
        print_text_report(reports)
