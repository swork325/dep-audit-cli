"""Transitive dependency detection — flags packages that appear only as
transitive (indirect) dependencies rather than direct requirements."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class TransitiveEntry:
    name: str
    current_version: Optional[str]
    required_by: List[str]  # direct packages that pull this in
    is_direct: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "current_version": self.current_version,
            "required_by": self.required_by,
            "is_direct": self.is_direct,
        }


@dataclass
class TransitiveReport:
    entries: List[TransitiveEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def indirect_count(self) -> int:
        return sum(1 for e in self.entries if not e.is_direct)

    @property
    def direct_count(self) -> int:
        return sum(1 for e in self.entries if e.is_direct)

    def find(self, name: str) -> Optional[TransitiveEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None

    def indirect_only(self) -> List[TransitiveEntry]:
        return [e for e in self.entries if not e.is_direct]


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_")


def build_transitive_report(
    report: AuditReport,
    dep_tree: Optional[Dict[str, List[str]]] = None,
) -> TransitiveReport:
    """Build a TransitiveReport from an AuditReport.

    ``dep_tree`` maps a normalised package name to the list of direct
    package names that declare it as a dependency.  When omitted every
    dep is treated as direct.
    """
    tree: Dict[str, List[str]] = dep_tree or {}

    direct_names: Set[str] = set()
    for fa in report.files:
        for dep in fa.deps:
            direct_names.add(_normalise(dep.name))

    seen: Dict[str, TransitiveEntry] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = _normalise(dep.name)
            required_by = tree.get(key, [])
            is_direct = key in direct_names and not required_by
            if key not in seen:
                seen[key] = TransitiveEntry(
                    name=dep.name,
                    current_version=dep.current_version,
                    required_by=required_by,
                    is_direct=is_direct or not required_by,
                )
    return TransitiveReport(entries=list(seen.values()))
