"""Identify unused/redundant dependencies by cross-referencing declared deps
against a simple import scan of Python source files in the project root."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class PruneCandidate:
    name: str
    current_version: str | None
    reason: str  # 'no_import_found' | 'duplicate_declaration'


@dataclass
class PruneReport:
    candidates: list[PruneCandidate] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.candidates)

    def by_reason(self, reason: str) -> list[PruneCandidate]:
        return [c for c in self.candidates if c.reason == reason]


def _collect_imports(source_root: Path) -> set[str]:
    """Walk *source_root* and collect all top-level import names."""
    names: set[str] = set()
    for py_file in source_root.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module.split(".")[0].lower())
    return names


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def _all_deps(report: AuditReport) -> list[ResolvedDep]:
    seen: dict[str, ResolvedDep] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = _normalize(dep.name)
            if key not in seen:
                seen[key] = dep
    return list(seen.values())


def _find_duplicates(report: AuditReport) -> set[str]:
    """Return normalised names declared in more than one requirements file."""
    counts: dict[str, int] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = _normalize(dep.name)
            counts[key] = counts.get(key, 0) + 1
    return {name for name, count in counts.items() if count > 1}


def build_prune_report(
    report: AuditReport,
    source_root: str | os.PathLike = ".",
) -> PruneReport:
    """Return a :class:`PruneReport` for *report* given *source_root*."""
    imported = _collect_imports(Path(source_root))
    duplicates = _find_duplicates(report)
    candidates: list[PruneCandidate] = []

    for dep in _all_deps(report):
        key = _normalize(dep.name)
        if key in duplicates:
            candidates.append(
                PruneCandidate(dep.name, dep.current_version, "duplicate_declaration")
            )
        elif key not in imported:
            candidates.append(
                PruneCandidate(dep.name, dep.current_version, "no_import_found")
            )

    return PruneReport(candidates=candidates)
