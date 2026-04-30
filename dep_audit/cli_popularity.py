"""CLI integration for the popularity report feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_popularity import PopularityReport, build_popularity_report


def add_popularity_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("popularity")
    grp.add_argument(
        "--popularity",
        action="store_true",
        default=False,
        help="Fetch and display PyPI download stats for each dependency.",
    )
    grp.add_argument(
        "--popularity-format",
        choices=["text", "json"],
        default="text",
        dest="popularity_format",
        help="Output format for the popularity report (default: text).",
    )
    grp.add_argument(
        "--popularity-top",
        type=int,
        default=0,
        dest="popularity_top",
        help="Show only the top-N most downloaded packages (0 = all).",
    )


def _render_text(pop: PopularityReport, top: int) -> str:
    lines = ["\n=== Popularity Report ==="]
    entries = pop.top(top) if top > 0 else pop.entries
    if not entries:
        lines.append("  No popularity data available.")
        return "\n".join(lines)
    col = ("Package", "Version", "Last Month", "Last Week", "Last Day")
    lines.append(f"  {col[0]:<30} {col[1]:<12} {col[2]:>12} {col[3]:>10} {col[4]:>10}")
    lines.append("  " + "-" * 76)
    for e in entries:
        lm = str(e.last_month) if e.last_month is not None else "n/a"
        lw = str(e.last_week) if e.last_week is not None else "n/a"
        ld = str(e.last_day) if e.last_day is not None else "n/a"
        lines.append(f"  {e.name:<30} {e.version:<12} {lm:>12} {lw:>10} {ld:>10}")
    return "\n".join(lines)


def _render_json(pop: PopularityReport, top: int) -> str:
    entries = pop.top(top) if top > 0 else pop.entries
    return json.dumps([e.to_dict() for e in entries], indent=2)


def maybe_render_popularity(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[PopularityReport]:
    import sys

    out = out or sys.stdout
    if not getattr(args, "popularity", False):
        return None
    pop = build_popularity_report(report)
    top = getattr(args, "popularity_top", 0)
    fmt = getattr(args, "popularity_format", "text")
    if fmt == "json":
        print(_render_json(pop, top), file=out)
    else:
        print(_render_text(pop, top), file=out)
    return pop
