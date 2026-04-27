"""CLI integration for the dependency chain tracer."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.tracer import TraceReport, build_trace


def add_tracer_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("tracer")
    grp.add_argument(
        "--trace",
        action="store_true",
        default=False,
        help="Show dependency chain / transitive relationships.",
    )
    grp.add_argument(
        "--trace-format",
        choices=["text", "json"],
        default="text",
        dest="trace_format",
        help="Output format for the trace report (default: text).",
    )
    grp.add_argument(
        "--trace-only-transitive",
        action="store_true",
        default=False,
        dest="trace_only_transitive",
        help="Only show transitive (non-direct) dependencies.",
    )


def _render_text(trace: TraceReport, only_transitive: bool) -> str:
    lines = ["Dependency Trace", "=" * 40]
    nodes = trace.transitive() if only_transitive else trace.nodes
    if not nodes:
        lines.append("  (no dependencies to display)")
        return "\n".join(lines)
    for node in sorted(nodes, key=lambda n: n.name.lower()):
        parents = ", ".join(node.required_by) if node.required_by else "(direct)"
        lines.append(f"  {node.name} {node.version or '?'}  <-  {parents}")
    lines.append(f"\nTotal: {len(nodes)}")
    return "\n".join(lines)


def _render_json(trace: TraceReport, only_transitive: bool) -> str:
    nodes = trace.transitive() if only_transitive else trace.nodes
    return json.dumps([n.to_dict() for n in nodes], indent=2)


def maybe_render_tracer(
    args: argparse.Namespace,
    report: AuditReport,
    extras: Optional[dict] = None,
) -> None:
    if not getattr(args, "trace", False):
        return
    trace = build_trace(report, extras=extras)
    only_transitive = getattr(args, "trace_only_transitive", False)
    fmt = getattr(args, "trace_format", "text")
    if fmt == "json":
        print(_render_json(trace, only_transitive))
    else:
        print(_render_text(trace, only_transitive))
