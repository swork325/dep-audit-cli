"""Policy engine: enforce rules on an AuditReport and collect violations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class PolicyRule:
    """A single named rule that can be violated."""
    name: str
    description: str


@dataclass
class PolicyViolation:
    rule: PolicyRule
    file_path: str
    dep: ResolvedDep
    detail: str


@dataclass
class PolicyResult:
    violations: List[PolicyViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0

    def by_rule(self, rule_name: str) -> List[PolicyViolation]:
        return [v for v in self.violations if v.rule.name == rule_name]


RULE_NO_OUTDATED = PolicyRule(
    name="no-outdated",
    description="All dependencies must be up to date.",
)
RULE_NO_VULNERABLE = PolicyRule(
    name="no-vulnerable",
    description="No dependency may have known vulnerabilities.",
)
RULE_NO_HIGH_VULN = PolicyRule(
    name="no-high-severity",
    description="No dependency may have high or critical vulnerabilities.",
)


def _max_severity(dep: ResolvedDep) -> Optional[str]:
    if not dep.vulns:
        return None
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return max(dep.vulns, key=lambda v: order.get(v.severity.lower(), 0)).severity.lower()


def check_policy(
    report: AuditReport,
    *,
    no_outdated: bool = False,
    no_vulnerable: bool = False,
    no_high_severity: bool = False,
) -> PolicyResult:
    result = PolicyResult()
    for fa in report.files:
        for dep in fa.deps:
            if no_outdated and dep.is_outdated:
                result.violations.append(PolicyViolation(
                    rule=RULE_NO_OUTDATED,
                    file_path=fa.path,
                    dep=dep,
                    detail=f"{dep.name} {dep.current_version} < {dep.latest_version}",
                ))
            if no_vulnerable and dep.vulns:
                result.violations.append(PolicyViolation(
                    rule=RULE_NO_VULNERABLE,
                    file_path=fa.path,
                    dep=dep,
                    detail=f"{dep.name} has {len(dep.vulns)} vulnerability/ies",
                ))
            elif no_high_severity and _max_severity(dep) in ("high", "critical"):
                result.violations.append(PolicyViolation(
                    rule=RULE_NO_HIGH_VULN,
                    file_path=fa.path,
                    dep=dep,
                    detail=f"{dep.name} has {_max_severity(dep)} severity vulnerability",
                ))
    return result
