"""Dependency churn analysis: tracks how frequently packages change versions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class ChurnEntry:
    name: str
    current_version: Optional[str]
    latest_version: Optional[str]
    change_count: int  # number of times seen changing across snapshots
    is_frequent: bool  # True when change_count >= threshold

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "change_count": self.change_count,
            "is_frequent": self.is_frequent,
        }


@dataclass
class ChurnReport:
    entries: List[ChurnEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def frequent_count(self) -> int:
        return sum(1 for e in self.entries if e.is_frequent)

    def find(self, name: str) -> Optional[ChurnEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None

    def frequent(self) -> List[ChurnEntry]:
        return [e for e in self.entries if e.is_frequent]


def build_churn_report(
    report: AuditReport,
    history: dict[str, int],
    threshold: int = 3,
) -> ChurnReport:
    """Build a ChurnReport from an AuditReport and a name->change_count history map."""
    seen: dict[str, ResolvedDep] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower().replace("-", "_")
            if key not in seen:
                seen[key] = dep

    entries: List[ChurnEntry] = []
    for key, dep in seen.items():
        count = history.get(key, 0)
        entries.append(
            ChurnEntry(
                name=dep.name,
                current_version=dep.current_version,
                latest_version=dep.latest_version,
                change_count=count,
                is_frequent=count >= threshold,
            )
        )
    entries.sort(key=lambda e: e.change_count, reverse=True)
    return ChurnReport(entries=entries)
