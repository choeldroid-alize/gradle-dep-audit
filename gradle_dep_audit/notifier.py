"""Notification module: emit alerts when new vulnerabilities or regressions are detected."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional

from gradle_dep_audit.differ import DiffResult


@dataclass
class NotificationPayload:
    """Structured payload summarising what changed."""
    new_vulnerable: int
    new_outdated: int
    fixed: int
    details: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return self.new_vulnerable == 0 and self.new_outdated == 0

    def to_dict(self) -> dict:
        return {
            "new_vulnerable": self.new_vulnerable,
            "new_outdated": self.new_outdated,
            "fixed": self.fixed,
            "details": self.details,
        }


def build_payload(diff: DiffResult) -> NotificationPayload:
    """Convert a DiffResult into a NotificationPayload."""
    details: List[str] = []
    new_vuln = 0
    new_outdated = 0

    for row in diff.added:
        dep = row.get("dependency")
        coord = dep.coordinate() if dep else "unknown"
        vulns = row.get("vulnerabilities") or []
        if vulns:
            new_vuln += 1
            ids = ", ".join(v.get("id", "?") for v in vulns)
            details.append(f"NEW VULN  {coord}: {ids}")
        vi = row.get("version_info")
        if vi and getattr(vi, "is_outdated", False):
            new_outdated += 1
            details.append(f"NEW OUTDATED  {coord}: {vi.current} -> {vi.latest}")

    fixed = len(diff.removed)
    return NotificationPayload(
        new_vulnerable=new_vuln,
        new_outdated=new_outdated,
        fixed=fixed,
        details=details,
    )


def send_slack(payload: NotificationPayload, webhook_url: str, timeout: int = 10) -> bool:
    """POST a Slack-compatible message to *webhook_url*. Returns True on success."""
    if payload.is_empty():
        return True

    lines = ["*gradle-dep-audit alert*"]
    if payload.new_vulnerable:
        lines.append(f":red_circle: {payload.new_vulnerable} new vulnerable dep(s)")
    if payload.new_outdated:
        lines.append(f":warning: {payload.new_outdated} newly outdated dep(s)")
    if payload.fixed:
        lines.append(f":white_check_mark: {payload.fixed} issue(s) resolved")
    lines.extend(payload.details)

    body = json.dumps({"text": "\n".join(lines)}).encode()
    req = urllib.request.Request(
        webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except urllib.error.URLError:
        return False
