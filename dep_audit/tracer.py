"""Dependency chain tracer: surfaces transitive dependency relationships."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class TraceNode:
    name: str
    version: Optional[str]
    required_by: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "required_by": self.required_by,
        }


@dataclass
class TraceReport:
    nodes: List[TraceNode] = field(default_factory=list)

    def total(self) -> int:
        return len(self.nodes)

    def find(self, name: str) -> Optional[TraceNode]:
        key = name.lower().replace("-", "_")
        for node in self.nodes:
            if node.name.lower().replace("-", "_") == key:
                return node
        return None

    def transitive(self) -> List[TraceNode]:
        """Return nodes that are pulled in by other deps (not direct)."""
        return [n for n in self.nodes if n.required_by]

    def direct(self) -> List[TraceNode]:
        """Return nodes with no recorded parent (top-level deps)."""
        return [n for n in self.nodes if not n.required_by]


def _collect_deps(report: AuditReport) -> List[ResolvedDep]:
    seen: Dict[str, ResolvedDep] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower().replace("-", "_")
            if key not in seen:
                seen[key] = dep
    return list(seen.values())


def build_trace(report: AuditReport, extras: Optional[Dict[str, List[str]]] = None) -> TraceReport:
    """Build a TraceReport from an AuditReport.

    ``extras`` maps a package name to the list of packages that depend on it,
    allowing callers to inject transitive information (e.g. from pip-tools output).
    """
    extras = extras or {}
    nodes: List[TraceNode] = []
    for dep in _collect_deps(report):
        key = dep.name.lower().replace("-", "_")
        required_by = extras.get(key, extras.get(dep.name, []))
        nodes.append(TraceNode(name=dep.name, version=dep.current, required_by=required_by))
    return TraceReport(nodes=nodes)
