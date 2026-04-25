"""Generate shield-style badge data for a project audit report."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from dep_audit.auditor import AuditReport

Color = Literal["brightgreen", "green", "yellow", "orange", "red"]


@dataclass(frozen=True)
class BadgeData:
    label: str
    message: str
    color: Color
    schema_version: int = 1

    def to_dict(self) -> dict:
        return {
            "schemaVersion": self.schema_version,
            "label": self.label,
            "message": self.message,
            "color": self.color,
        }


def _pick_color(outdated: int, vulnerable: int) -> Color:
    if vulnerable > 0:
        return "red"
    if outdated >= 10:
        return "orange"
    if outdated >= 5:
        return "yellow"
    if outdated >= 1:
        return "green"
    return "brightgreen"


def _build_message(outdated: int, vulnerable: int) -> str:
    parts: list[str] = []
    if vulnerable:
        parts.append(f"{vulnerable} vuln")
    if outdated:
        parts.append(f"{outdated} outdated")
    return ", ".join(parts) if parts else "up to date"


def build_badge(report: AuditReport, label: str = "dependencies") -> BadgeData:
    """Return a BadgeData instance summarising the audit report."""
    outdated_count = sum(
        len(fa.outdated()) for fa in report.file_audits
    )
    vuln_count = sum(
        sum(1 for d in fa.deps if d.vulns)
        for fa in report.file_audits
    )
    return BadgeData(
        label=label,
        message=_build_message(outdated_count, vuln_count),
        color=_pick_color(outdated_count, vuln_count),
    )
