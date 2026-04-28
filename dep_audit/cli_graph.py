"""CLI integration for the dependency graph feature."""
from __future__ import annotations

import argparse
import json
from typing import Any

from dep_audit.auditor import AuditReport
from dep_audit.auditor_graph import DependencyGraph, build_graph


def add_graph_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--graph",
        action="store_true",
        default=False,
        help="Print the dependency graph.",
    )
    parser.add_argument(
        "--graph-format",
        choices=["text", "json"],
        default="text",
        dest="graph_format",
        help="Output format for the dependency graph (default: text).",
    )
    parser.add_argument(
        "--graph-root",
        default=None,
        dest="graph_root",
        metavar="PACKAGE",
        help="Show only edges reachable from this root package.",
    )


def _render_text(graph: DependencyGraph, root: str | None) -> str:
    lines: list[str] = ["Dependency Graph", "=" * 40]
    nodes = (
        [graph.find(root)] if root and graph.find(root) else graph.nodes.values()
    )
    for node in nodes:
        if node is None:
            continue
        deps_str = ", ".join(node.dependencies) if node.dependencies else "(none)"
        lines.append(f"  {node.name}  ->  {deps_str}")
    lines.append(f"\nTotal packages: {graph.total}")
    lines.append(f"Roots (top-level): {', '.join(graph.roots()) or '(none)'}")
    return "\n".join(lines)


def _render_json(graph: DependencyGraph) -> str:
    data: dict[str, Any] = {
        "total": graph.total,
        "roots": graph.roots(),
        "leaves": graph.leaves(),
        "nodes": {k: v.to_dict() for k, v in graph.nodes.items()},
    }
    return json.dumps(data, indent=2)


def maybe_render_graph(
    args: argparse.Namespace,
    report: AuditReport,
    print_fn=print,
) -> None:
    if not getattr(args, "graph", False):
        return
    graph = build_graph(report)
    root = getattr(args, "graph_root", None)
    fmt = getattr(args, "graph_format", "text")
    if fmt == "json":
        print_fn(_render_json(graph))
    else:
        print_fn(_render_text(graph, root))
