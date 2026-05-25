"""Persist and load audit result snapshots for diff comparisons."""

from __future__ import annotations

import json
import os
from typing import List

from gradle_dep_audit.parser import Dependency
from gradle_dep_audit.checker import VulnerabilityReport
from gradle_dep_audit.resolver import VersionInfo

_DEFAULT_SNAPSHOT_DIR = ".gradle_dep_audit_snapshots"


def _row_to_dict(row: dict) -> dict:
    dep: Dependency = row["dependency"]
    vi: VersionInfo | None = row.get("version_info")
    vr: VulnerabilityReport | None = row.get("vulnerability_report")
    return {
        "dependency": {
            "group": dep.group,
            "artifact": dep.artifact,
            "version": dep.version,
        },
        "version_info": {
            "current": vi.current if vi else dep.version,
            "latest": vi.latest if vi else dep.version,
            "is_outdated": vi.is_outdated if vi else False,
        },
        "vulnerability_report": {
            "purl": vr.purl if vr else "",
            "vulnerabilities": vr.vulnerabilities if vr else [],
        },
    }


def _dict_to_row(data: dict) -> dict:
    d = data["dependency"]
    dep = Dependency(group=d["group"], artifact=d["artifact"], version=d["version"])
    vi_d = data["version_info"]
    vi = VersionInfo(current=vi_d["current"], latest=vi_d["latest"], is_outdated=vi_d["is_outdated"])
    vr_d = data["vulnerability_report"]
    vr = VulnerabilityReport(purl=vr_d["purl"], vulnerabilities=vr_d["vulnerabilities"])
    return {"dependency": dep, "version_info": vi, "vulnerability_report": vr}


def save_snapshot(rows: List[dict], name: str, snapshot_dir: str = _DEFAULT_SNAPSHOT_DIR) -> str:
    """Serialize audit rows to a JSON snapshot file.

    Returns the path of the written file.
    """
    os.makedirs(snapshot_dir, exist_ok=True)
    path = os.path.join(snapshot_dir, f"{name}.json")
    payload = [_row_to_dict(r) for r in rows]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def load_snapshot(name: str, snapshot_dir: str = _DEFAULT_SNAPSHOT_DIR) -> List[dict]:
    """Load audit rows from a previously saved snapshot file.

    Raises FileNotFoundError if the snapshot does not exist.
    """
    path = os.path.join(snapshot_dir, f"{name}.json")
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return [_dict_to_row(item) for item in payload]


def list_snapshots(snapshot_dir: str = _DEFAULT_SNAPSHOT_DIR) -> List[str]:
    """Return snapshot names (without extension) available in *snapshot_dir*."""
    if not os.path.isdir(snapshot_dir):
        return []
    return [
        os.path.splitext(f)[0]
        for f in sorted(os.listdir(snapshot_dir))
        if f.endswith(".json")
    ]
