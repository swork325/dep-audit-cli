"""remediation.py – generate actionable remediation commands for outdated/vulnerable deps.

For each dependency that has issues, this module produces a shell command
(e.g. ``pip install --upgrade requests==2.32.0``) that a developer can run
directly to resolve the problem.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


@dataclass
class RemediationCommand:
    """A single pip command that addresses one dependency issue."""

    package: str
    current_version: Optional[str]
    target_version: Optional[str]
    reason: str  # e.g. "outdated", "vulnerable", "outdated+vulnerable"
    command: str  # the shell command string

    def __str__(self) -> str:  # pragma: no cover
        return self.command


@dataclass
class RemediationPlan:
    """Collected remediation commands for an entire audit report."""

    commands: List[RemediationCommand] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.commands)

    def for_package(self, name: str) -> List[RemediationCommand]:
        """Return all commands for a given package name (case-insensitive)."""
        key = name.lower()
        return [c for c in self.commands if c.package.lower() == key]


def _reason(dep: ResolvedDep) -> str:
    """Derive a human-readable reason string from a dep's flags."""
    flags = []
    if dep.is_outdated:
        flags.append("outdated")
    if dep.vulnerabilities:
        flags.append("vulnerable")
    return "+".join(flags) if flags else "unknown"


def _build_command(dep: ResolvedDep) -> Optional[str]:
    """Return a pip install command string, or None if no target version is known."""
    target = dep.latest_version
    if not target:
        # No known latest – suggest an upgrade without pinning
        return f"pip install --upgrade {dep.name}"
    return f"pip install {dep.name}=={target}"


def remediation_for_dep(dep: ResolvedDep) -> Optional[RemediationCommand]:
    """Build a RemediationCommand for a single dep, or None if no action needed."""
    if not dep.is_outdated and not dep.vulnerabilities:
        return None

    cmd_str = _build_command(dep)
    if cmd_str is None:
        return None

    return RemediationCommand(
        package=dep.name,
        current_version=dep.current_version,
        target_version=dep.latest_version,
        reason=_reason(dep),
        command=cmd_str,
    )


def build_remediation_plan(report: AuditReport) -> RemediationPlan:
    """Produce a RemediationPlan for every dep with issues across all files."""
    seen: set[str] = set()
    commands: List[RemediationCommand] = []

    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower()
            if key in seen:
                # Emit only one command per package even if it appears in multiple files
                continue
            cmd = remediation_for_dep(dep)
            if cmd is not None:
                commands.append(cmd)
                seen.add(key)

    return RemediationPlan(commands=commands)


def render_remediation_text(plan: RemediationPlan) -> str:
    """Render the remediation plan as a human-readable block of shell commands."""
    if not plan.commands:
        return "No remediation required – all dependencies are up-to-date and secure.\n"

    lines = [f"# {plan.total} remediation command(s) suggested:\n"]
    for cmd in plan.commands:
        lines.append(f"# {cmd.package}  ({cmd.reason})")
        lines.append(cmd.command)
        lines.append("")
    return "\n".join(lines)


def render_remediation_json(plan: RemediationPlan) -> list:
    """Render the remediation plan as a list of dicts (JSON-serialisable)."""
    return [
        {
            "package": c.package,
            "current_version": c.current_version,
            "target_version": c.target_version,
            "reason": c.reason,
            "command": c.command,
        }
        for c in plan.commands
    ]
