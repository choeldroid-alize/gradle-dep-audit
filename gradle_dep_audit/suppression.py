"""Suppression list: ignore known issues by coordinate + vuln ID until an expiry date."""
from __future__ import annotations

import json
import os
from datetime import date, datetime
from typing import Any

_DATE_FMT = "%Y-%m-%d"


def _today() -> date:
    return datetime.utcnow().date()


def _coord(row: dict) -> str:
    dep = row.get("dependency")
    if dep is None:
        return ""
    return f"{dep.group}:{dep.artifact}:{dep.version}"


def load_suppression(path: str) -> list[dict]:
    """Load a JSON suppression file.  Returns [] if the file does not exist."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("suppressions", [])


def save_suppression(path: str, suppressions: list[dict]) -> None:
    """Persist a suppression list to *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"suppressions": suppressions}, fh, indent=2)


def _entry_matches(entry: dict, coord: str, vuln_id: str) -> bool:
    """Return True when *entry* covers *coord* / *vuln_id* and has not expired."""
    if entry.get("coordinate", "") != coord:
        return False
    if entry.get("vuln_id", "") not in (vuln_id, "*"):
        return False
    expires_raw = entry.get("expires")
    if expires_raw:
        try:
            expires = datetime.strptime(expires_raw, _DATE_FMT).date()
            if _today() > expires:
                return False
        except ValueError:
            pass
    return True


def is_suppressed(suppressions: list[dict], row: dict, vuln_id: str) -> bool:
    """Return True when *vuln_id* for the dependency in *row* is suppressed."""
    coord = _coord(row)
    return any(_entry_matches(e, coord, vuln_id) for e in suppressions)


def apply_suppressions(suppressions: list[dict], rows: list[dict]) -> list[dict]:
    """Remove suppressed vulnerability IDs from each row's VulnerabilityReport."""
    import copy
    result = []
    for row in rows:
        row = copy.deepcopy(row)
        vr = row.get("vulnerability_report")
        if vr and vr.vulnerabilities:
            vr.vulnerabilities = [
                v for v in vr.vulnerabilities
                if not is_suppressed(suppressions, row, v.get("id", ""))
            ]
        result.append(row)
    return result
