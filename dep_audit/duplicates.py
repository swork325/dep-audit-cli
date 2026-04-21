"""Detect duplicate dependencies declared across multiple requirement files."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class DuplicateEntry:
    """A package that appears in more than one file."""

    package: str
    occurrences: List[str] = field(default_factory=list)  # file paths
    versions: List[str] = field(default_factory=list)  # pinned versions per file

    @property
    def has_version_conflict(self) -> bool:
        """Return True when the same package is pinned to different versions."""
        pinned = [v for v in self.versions if v]
        return len(set(pinned)) > 1 if pinned else False


@dataclass
class DuplicatesReport:
    """Aggregated duplicates across an AuditReport."""

    entries: List[DuplicateEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def conflicts(self) -> List[DuplicateEntry]:
        return [e for e in self.entries if e.has_version_conflict]


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def find_duplicates(report: AuditReport) -> DuplicatesReport:
    """Scan *report* and return every package declared in more than one file."""
    # Map normalised package name -> list of (file_path, pinned_version)
    seen: Dict[str, List[tuple]] = defaultdict(list)

    for file_audit in report.files:
        for dep in file_audit.deps:
            key = _normalize(dep.name)
            seen[key].append((file_audit.path, dep.current_version or ""))

    entries: List[DuplicateEntry] = []
    for pkg, occurrences in seen.items():
        if len(occurrences) > 1:
            entries.append(
                DuplicateEntry(
                    package=pkg,
                    occurrences=[o[0] for o in occurrences],
                    versions=[o[1] for o in occurrences],
                )
            )

    entries.sort(key=lambda e: e.package)
    return DuplicatesReport(entries=entries)


def render_duplicates_text(dup_report: DuplicatesReport) -> str:
    """Return a human-readable summary of duplicate dependencies."""
    if not dup_report.total:
        return "No duplicate dependencies found.\n"

    lines = [f"Duplicate dependencies ({dup_report.total} packages):\n"]
    for entry in dup_report.entries:
        conflict_flag = " [VERSION CONFLICT]" if entry.has_version_conflict else ""
        lines.append(f"  {entry.package}{conflict_flag}")
        for path, ver in zip(entry.occurrences, entry.versions):
            ver_str = f" ({ver})" if ver else ""
            lines.append(f"    - {path}{ver_str}")
    return "\n".join(lines) + "\n"
