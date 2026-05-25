"""Policy engine: enforce rules on audit results and produce violations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gradle_dep_audit.scorer import RiskScore


@dataclass
class PolicyRule:
    """A single named policy rule with a threshold."""
    name: str
    description: str
    # callable(row: dict) -> bool  — True means the row violates the rule
    predicate: Any = field(repr=False)


@dataclass
class PolicyViolation:
    rule_name: str
    coordinate: str
    detail: str

    def __repr__(self) -> str:  # pragma: no cover
        return f"PolicyViolation(rule={self.rule_name!r}, coord={self.coordinate!r})"


def _coord(row: dict) -> str:
    dep = row.get("dependency")
    return dep.coordinate() if dep else "unknown"


def check_policy(rows: list[dict], rules: list[PolicyRule]) -> list[PolicyViolation]:
    """Return every violation found across *rows* for each rule in *rules*."""
    violations: list[PolicyViolation] = []
    for row in rows:
        for rule in rules:
            if rule.predicate(row):
                violations.append(
                    PolicyViolation(
                        rule_name=rule.name,
                        coordinate=_coord(row),
                        detail=rule.description,
                    )
                )
    return violations


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------

def rule_block_critical() -> PolicyRule:
    """Fail on any dependency with a CRITICAL vulnerability."""
    def _pred(row: dict) -> bool:
        vr = row.get("vulnerability_report")
        if vr is None:
            return False
        return any(
            (v.get("severity") or "").upper() == "CRITICAL"
            for v in (vr.vulnerabilities or [])
        )
    return PolicyRule("block_critical", "CRITICAL vulnerability detected", _pred)


def rule_max_risk_score(threshold: int) -> PolicyRule:
    """Fail when the computed risk score exceeds *threshold*."""
    def _pred(row: dict) -> bool:
        rs: RiskScore | None = row.get("risk_score")
        return rs is not None and rs.score > threshold
    return PolicyRule(
        "max_risk_score",
        f"Risk score exceeds threshold ({threshold})",
        _pred,
    )


def rule_no_outdated() -> PolicyRule:
    """Fail on any dependency that is outdated."""
    def _pred(row: dict) -> bool:
        vi = row.get("version_info")
        return vi is not None and vi.is_outdated
    return PolicyRule("no_outdated", "Dependency is outdated", _pred)
