"""Pinning audit: check whether each resolved dep is pinned to an exact version."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_EXACT_PIN_RE = re.compile(r"^[A-Za-z0-9_.+-]+==[^,;\s]+$")


@dataclass
class PinningEntry:
    name: str
    current_version: Optional[str]
    raw_spec: Optional[str]
    pinned: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "current_version": self.current_version,
            "raw_spec": self.raw_spec,
            "pinned": self.pinned,
        }


@dataclass
class PinningReport:
    entries: List[PinningEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def unpinned_count(self) -> int:
        return sum(1 for e in self.entries if not e.pinned)

    @property
    def pin_rate(self) -> float:
        if not self.entries:
            return 1.0
        return sum(1 for e in self.entries if e.pinned) / len(self.entries)

    def unpinned(self) -> List[PinningEntry]:
        return [e for e in self.entries if not e.pinned]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "unpinned_count": self.unpinned_count,
            "pin_rate": round(self.pin_rate, 4),
            "entries": [e.to_dict() for e in self.entries],
        }


def _is_pinned(raw_spec: Optional[str]) -> bool:
    """Return True when *raw_spec* represents an exact ``==`` pin."""
    if not raw_spec:
        return False
    return bool(_EXACT_PIN_RE.match(raw_spec.strip()))


def _collect_deps(report: AuditReport) -> List[ResolvedDep]:
    seen: set = set()
    deps: List[ResolvedDep] = []
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key not in seen:
                seen.add(key)
                deps.append(dep)
    return deps


def build_pinning_report(report: AuditReport) -> PinningReport:
    """Inspect every unique dep in *report* and classify its pinning status."""
    entries: List[PinningEntry] = []
    for dep in _collect_deps(report):
        raw = dep.raw_spec if hasattr(dep, "raw_spec") else None
        # Fall back to reconstructing spec from resolved version
        if raw is None and dep.current_version:
            raw = f"{dep.name}=={dep.current_version}"
        pinned = _is_pinned(raw)
        entries.append(
            PinningEntry(
                name=dep.name,
                current_version=dep.current_version,
                raw_spec=raw,
                pinned=pinned,
            )
        )
    return PinningReport(entries=entries)
