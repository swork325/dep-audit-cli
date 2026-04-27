"""CLI integration for the dependency heatmap feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.heatmap import build_heatmap, Heatmap


def add_heatmap_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("heatmap")
    group.add_argument(
        "--heatmap",
        action="store_true",
        default=False,
        help="Show a risk heatmap ranked by file score.",
    )
    group.add_argument(
        "--heatmap-format",
        choices=["text", "json"],
        default="text",
        dest="heatmap_format",
        help="Output format for the heatmap (default: text).",
    )
    group.add_argument(
        "--heatmap-top",
        type=int,
        default=0,
        dest="heatmap_top",
        metavar="N",
        help="Limit output to the top N hottest files (0 = all).",
    )


def _render_text(heatmap: Heatmap, top: int) -> str:
    lines = ["=== Dependency Heatmap ==="]
    entries = heatmap.entries[:top] if top > 0 else heatmap.entries
    if not entries:
        lines.append("  (no data)")
        return "\n".join(lines)
    for rank, entry in enumerate(entries, 1):
        lines.append(
            f"  {rank:>3}. [{entry.score:>4}] {entry.path}"
            f"  (outdated={entry.outdated_count}, vulns={entry.vuln_count})"
        )
    lines.append(f"Total heatmap score: {heatmap.total_score}")
    return "\n".join(lines)


def _render_json(heatmap: Heatmap, top: int) -> str:
    entries = heatmap.entries[:top] if top > 0 else heatmap.entries
    payload = {
        "total_score": heatmap.total_score,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_heatmap(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    print_fn=print,
) -> None:
    if not getattr(args, "heatmap", False):
        return
    heatmap = build_heatmap(report)
    top = getattr(args, "heatmap_top", 0)
    fmt = getattr(args, "heatmap_format", "text")
    if fmt == "json":
        print_fn(_render_json(heatmap, top))
    else:
        print_fn(_render_text(heatmap, top))
