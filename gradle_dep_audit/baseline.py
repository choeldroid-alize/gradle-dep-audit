"""Baseline management: mark current audit results as an accepted baseline
so future runs only report *new* issues relative to that baseline."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

DEFAULT_BASELINE_FILE = ".gradle_dep_audit_baseline.json"


def _row_key(row: dict) -> str:
    """Stable string key identifying a (dependency, vuln-id) pair."""
    dep = row.get("dependency", "")
    vuln_ids = sorted(row.get("vuln_ids", []))
    return f"{dep}|{'|'.join(vuln_ids)}"


def save_baseline(rows: List[dict], path: str = DEFAULT_BASELINE_FILE) -> None:
    """Persist *rows* as the accepted baseline.

    Only entries that carry at least one vulnerability are stored because
    outdated-only findings are considered informational rather than actionable
    security issues.
    """
    baseline: List[dict] = [
        {"key": _row_key(r), "dependency": r.get("dependency", ""),
         "vuln_ids": sorted(r.get("vuln_ids", []))}
        for r in rows
        if r.get("vuln_ids")
    ]
    Path(path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: str = DEFAULT_BASELINE_FILE) -> Optional[set]:
    """Return the set of baseline keys, or *None* if no baseline file exists."""
    if not os.path.exists(path):
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {entry["key"] for entry in data}


def filter_new_issues(rows: List[dict], baseline_keys: set) -> List[dict]:
    """Return only rows whose key is NOT present in *baseline_keys*."""
    return [r for r in rows if _row_key(r) not in baseline_keys]


def apply_baseline(
    rows: List[dict],
    baseline_path: str = DEFAULT_BASELINE_FILE,
) -> List[dict]:
    """High-level helper: load the baseline and filter *rows* accordingly.

    If no baseline file is found the original *rows* list is returned unchanged.
    """
    keys = load_baseline(baseline_path)
    if keys is None:
        return rows
    return filter_new_issues(rows, keys)
