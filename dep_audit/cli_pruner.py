"""CLI integration for the pruner feature."""
from __future__ import annotations

import argparse
import json

from dep_audit.auditor import AuditReport
from dep_audit.pruner import PruneReport, build_prune_report


def add_pruner_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--prune",
        action="store_true",
        default=False,
        help="Show dependencies that may be unused or declared multiple times.",
    )
    parser.add_argument(
        "--prune-source-root",
        default=".",
        metavar="DIR",
        help="Root directory to scan for Python imports (default: current directory).",
    )
    parser.add_argument(
        "--prune-format",
        choices=["text", "json"],
        default="text",
        help="Output format for prune report (default: text).",
    )


def _render_text(prune: PruneReport) -> str:
    if prune.total == 0:
        return "prune: no candidates found — all declared deps appear to be used.\n"
    lines = [f"prune: {prune.total} candidate(s) found\n"]
    for c in prune.candidates:
        ver = c.current_version or "unpinned"
        lines.append(f"  {c.name} ({ver})  [{c.reason}]")
    return "\n".join(lines) + "\n"


def _render_json(prune: PruneReport) -> str:
    data = {
        "total": prune.total,
        "candidates": [
            {
                "name": c.name,
                "current_version": c.current_version,
                "reason": c.reason,
            }
            for c in prune.candidates
        ],
    }
    return json.dumps(data, indent=2)


def maybe_render_pruner(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    print_fn=print,
) -> None:
    if not getattr(args, "prune", False):
        return
    source_root = getattr(args, "prune_source_root", ".")
    fmt = getattr(args, "prune_format", "text")
    prune = build_prune_report(report, source_root=source_root)
    output = _render_json(prune) if fmt == "json" else _render_text(prune)
    print_fn(output)
