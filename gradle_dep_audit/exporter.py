"""Export audit results to various file formats (JSON, CSV, HTML)."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import List, Tuple

from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.resolver import VersionInfo


AuditRow = Tuple[Dependency, VersionInfo, VulnerabilityReport]


def export_json(rows: List[AuditRow]) -> str:
    """Serialise audit results to a JSON string."""
    payload = []
    for dep, vi, vr in rows:
        payload.append(
            {
                "coordinate": dep.coordinate,
                "group": dep.group,
                "artifact": dep.artifact,
                "version": dep.version,
                "latest_version": vi.latest_version,
                "outdated": vi.outdated,
                "vulnerabilities": [
                    {"id": v.get("id", ""), "severity": v.get("severity", "UNKNOWN")}
                    for v in (vr.vulnerabilities if vr else [])
                ],
            }
        )
    return json.dumps(payload, indent=2)


def export_csv(rows: List[AuditRow]) -> str:
    """Serialise audit results to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["coordinate", "current_version", "latest_version", "outdated", "vuln_count", "vuln_ids"]
    )
    for dep, vi, vr in rows:
        vuln_ids = "|".join(v.get("id", "") for v in (vr.vulnerabilities if vr else []))
        writer.writerow(
            [
                dep.coordinate,
                dep.version,
                vi.latest_version or "",
                str(vi.outdated),
                len(vr.vulnerabilities) if vr else 0,
                vuln_ids,
            ]
        )
    return output.getvalue()


def export_html(rows: List[AuditRow]) -> str:
    """Serialise audit results to a minimal HTML report string."""
    lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Gradle Dependency Audit</title></head><body>",
        "<h1>Gradle Dependency Audit</h1>",
        "<table border='1' cellpadding='4' cellspacing='0'>",
        "<tr><th>Coordinate</th><th>Current</th><th>Latest</th>"
        "<th>Outdated</th><th>Vulnerabilities</th></tr>",
    ]
    for dep, vi, vr in rows:
        vulns = ", ".join(v.get("id", "") for v in (vr.vulnerabilities if vr else []))
        outdated_cell = "<td style='color:orange'>Yes</td>" if vi.outdated else "<td>No</td>"
        vuln_cell = (
            f"<td style='color:red'>{vulns}</td>" if vulns else "<td style='color:green'>None</td>"
        )
        lines.append(
            f"<tr><td>{dep.coordinate}</td><td>{dep.version}</td>"
            f"<td>{vi.latest_version or 'N/A'}</td>{outdated_cell}{vuln_cell}</tr>"
        )
    lines.append("</table></body></html>")
    return "\n".join(lines)


def export(rows: List[AuditRow], fmt: str) -> str:
    """Dispatch to the correct exporter based on *fmt* ('json', 'csv', 'html')."""
    fmt = fmt.lower()
    if fmt == "json":
        return export_json(rows)
    if fmt == "csv":
        return export_csv(rows)
    if fmt == "html":
        return export_html(rows)
    raise ValueError(f"Unsupported export format: {fmt!r}")
