"""Temporary exemptions: time-boxed suppressions that auto-expire."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit

DEFAULT_EXEMPTIONS_FILE = ".dep-audit-exemptions.json"


@dataclass
class Exemption:
    package: str
    reason: str
    expires: datetime
    added_by: str = "unknown"

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        exp = self.expires
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
            "added_by": self.added_by,
        }

    @staticmethod
    def from_dict(d: dict) -> "Exemption":
        return Exemption(
            package=d["package"].lower(),
            reason=d.get("reason", ""),
            expires=datetime.fromisoformat(d["expires"]),
            added_by=d.get("added_by", "unknown"),
        )


def load_exemptions(path: str = DEFAULT_EXEMPTIONS_FILE) -> List[Exemption]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, list):
            return []
        return [Exemption.from_dict(e) for e in data]
    except (json.JSONDecodeError, KeyError, ValueError):
        return []


def save_exemptions(exemptions: List[Exemption], path: str = DEFAULT_EXEMPTIONS_FILE) -> None:
    Path(path).write_text(json.dumps([e.to_dict() for e in exemptions], indent=2))


def active_exemptions(exemptions: List[Exemption], now: Optional[datetime] = None) -> Dict[str, Exemption]:
    """Return mapping of package -> Exemption for non-expired entries."""
    return {e.package: e for e in exemptions if not e.is_expired(now)}


def apply_exemptions(report: AuditReport, exemptions: List[Exemption],
                     now: Optional[datetime] = None) -> AuditReport:
    """Remove deps covered by an active exemption from every FileAudit."""
    active = active_exemptions(exemptions, now)
    new_files: List[FileAudit] = []
    for fa in report.files:
        kept = [d for d in fa.deps if d.name.lower() not in active]
        new_files.append(FileAudit(path=fa.path, deps=kept))
    return AuditReport(files=new_files)
