"""Diff two AuditReports to surface packages whose versions have changed
between runs, making it easy to spot what actually moved."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class VersionChange:
    name: str
    old_version: Optional[str]
    new_version: Optional[str]
    was_outdated: bool
    is_outdated: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "was_outdated": self.was_outdated,
            "is_outdated": self.is_outdated,
            "upgraded": self._upgraded(),
            "downgraded": self._downgraded(),
        }

    def _upgraded(self) -> bool:
        return (
            self.old_version is not None
            and self.new_version is not None
            and self.new_version != self.old_version
            and not self._downgraded()
        )

    def _downgraded(self) -> bool:
        if self.old_version is None or self.new_version is None:
            return False
        try:
            from packaging.version import Version  # type: ignore
            return Version(self.new_version) < Version(self.old_version)
        except Exception:
            return False


@dataclass
class ChangelogDiffReport:
    changes: List[VersionChange] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.changes)

    @property
    def upgraded(self) -> List[VersionChange]:
        return [c for c in self.changes if c._upgraded()]

    @property
    def downgraded(self) -> List[VersionChange]:
        return [c for c in self.changes if c._downgraded()]

    @property
    def newly_outdated(self) -> List[VersionChange]:
        return [c for c in self.changes if c.is_outdated and not c.was_outdated]


def _dep_map(report: AuditReport) -> Dict[str, ResolvedDep]:
    result: Dict[str, ResolvedDep] = {}
    for fa in report.files:
        for dep in fa.deps:
            result[dep.name.lower()] = dep
    return result


def build_changelog_diff(old: AuditReport, new: AuditReport) -> ChangelogDiffReport:
    """Return version changes for every package whose pinned version differs."""
    old_map = _dep_map(old)
    new_map = _dep_map(new)
    all_names = set(old_map) | set(new_map)
    changes: List[VersionChange] = []
    for name in sorted(all_names):
        old_dep = old_map.get(name)
        new_dep = new_map.get(name)
        old_ver = old_dep.current_version if old_dep else None
        new_ver = new_dep.current_version if new_dep else None
        if old_ver == new_ver:
            continue
        changes.append(
            VersionChange(
                name=name,
                old_version=old_ver,
                new_version=new_ver,
                was_outdated=bool(old_dep and old_dep.is_outdated),
                is_outdated=bool(new_dep and new_dep.is_outdated),
            )
        )
    return ChangelogDiffReport(changes=changes)
