"""Pinboard: track which dependencies are pinned to exact versions and suggest pinning."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class PinStatus:
    name: str
    current_version: Optional[str]
    latest_version: Optional[str]
    is_pinned: bool
    is_outdated: bool
    suggested_pin: Optional[str]


@dataclass
class PinboardReport:
    pinned: List[PinStatus] = field(default_factory=list)
    unpinned: List[PinStatus] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.pinned) + len(self.unpinned)

    @property
    def pin_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return len(self.pinned) / self.total


def _is_pinned(version: Optional[str]) -> bool:
    """Return True if version string looks like an exact pin (e.g. '==1.2.3')."""
    if not version:
        return False
    stripped = version.strip()
    return stripped.startswith("==") or (stripped and stripped[0].isdigit())


def _build_pin_status(dep: ResolvedDep) -> PinStatus:
    pinned = _is_pinned(dep.current_version)
    suggested = (
        f"=={dep.latest_version}" if dep.latest_version else None
    )
    return PinStatus(
        name=dep.name,
        current_version=dep.current_version,
        latest_version=dep.latest_version,
        is_pinned=pinned,
        is_outdated=dep.is_outdated,
        suggested_pin=suggested,
    )


def build_pinboard(report: AuditReport) -> PinboardReport:
    """Analyse all deps across an AuditReport and build a PinboardReport."""
    pb = PinboardReport()
    seen: set[str] = set()
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            status = _build_pin_status(dep)
            if status.is_pinned:
                pb.pinned.append(status)
            else:
                pb.unpinned.append(status)
    pb.pinned.sort(key=lambda s: s.name.lower())
    pb.unpinned.sort(key=lambda s: s.name.lower())
    return pb
