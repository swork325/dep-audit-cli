"""Dependency graph: build a simple directed graph of which packages
depend on which, derived from the current AuditReport."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class GraphNode:
    name: str
    dependents: List[str] = field(default_factory=list)   # packages that depend on this one
    dependencies: List[str] = field(default_factory=list)  # packages this one depends on

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "dependents": sorted(self.dependents),
            "dependencies": sorted(self.dependencies),
        }


@dataclass
class DependencyGraph:
    nodes: Dict[str, GraphNode] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.nodes)

    def roots(self) -> List[str]:
        """Packages that nothing else depends on (top-level deps)."""
        return sorted(n for n, node in self.nodes.items() if not node.dependents)

    def leaves(self) -> List[str]:
        """Packages that depend on nothing else."""
        return sorted(n for n, node in self.nodes.items() if not node.dependencies)

    def find(self, name: str) -> GraphNode | None:
        return self.nodes.get(name.lower().replace("-", "_"))


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_")


def _collect_all_deps(report: AuditReport) -> List[ResolvedDep]:
    deps: List[ResolvedDep] = []
    for fa in report.files:
        deps.extend(fa.deps)
    return deps


def build_graph(report: AuditReport, extras: Dict[str, List[str]] | None = None) -> DependencyGraph:
    """Build a DependencyGraph from an AuditReport.

    ``extras`` is an optional mapping of ``package_name -> [dep1, dep2, ...]``
    that provides known dependency relationships (e.g. from a lock file or
    manually supplied metadata).  Without it the graph contains all packages
    as isolated nodes.
    """
    extras = extras or {}
    graph = DependencyGraph()

    all_deps = _collect_all_deps(report)
    seen: Set[str] = set()

    for dep in all_deps:
        key = _normalise(dep.name)
        if key not in seen:
            seen.add(key)
            graph.nodes[key] = GraphNode(name=dep.name)

    for raw_name, raw_deps in extras.items():
        parent = _normalise(raw_name)
        if parent not in graph.nodes:
            graph.nodes[parent] = GraphNode(name=raw_name)
        for raw_child in raw_deps:
            child = _normalise(raw_child)
            if child not in graph.nodes:
                graph.nodes[child] = GraphNode(name=raw_child)
            if child not in graph.nodes[parent].dependencies:
                graph.nodes[parent].dependencies.append(child)
            if parent not in graph.nodes[child].dependents:
                graph.nodes[child].dependents.append(parent)

    return graph
