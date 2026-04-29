"""CLI integration for the freshness audit feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_freshness import FreshnessReport, build_freshness_report


def add_freshness_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("freshness")
    grp.add_argument(
        "--freshness",
        action="store_true",
        default=False,
        help="Show version-freshness analysis for all dependencies.",
    )
    grp.add_argument(
        "--freshness-format",
        choices=["text", "json"],
        default="text",
        dest="freshness_format",
        help="Output format for freshness report (default: text).",
    )
    grp.add_argument(
        "--freshness-major",
        type=int,
        default=1,
        dest="freshness_major",
        metavar="N",
        help="Major-version gap that marks a dep as stale (default: 1).",
    )
    grp.add_argument(
        "--freshness-minor",
        type=int,
        default=3,
        dest="freshness_minor",
        metavar="N",
        help="Minor-version gap that marks a dep as stale (default: 3).",
    )


def _render_text(fr: FreshnessReport) -> str:
    lines = ["Freshness Report", "=" * 40]
    if not fr.entries:
        lines.append("  (no dependencies found)")
        return "\n".join(lines)
    for e in fr.entries:
        tag = " [STALE]" if e.stale else ""
        lines.append(
            f"  {e.name}: {e.current or '?'} -> {e.latest or '?'}"
            f"  (major+{e.major_behind} minor+{e.minor_behind}){tag}"
        )
    lines.append("")
    lines.append(f"Total: {fr.total}  Stale: {fr.stale_count}")
    return "\n".join(lines)


def _render_json(fr: FreshnessReport) -> str:
    payload = {
        "total": fr.total,
        "stale_count": fr.stale_count,
        "entries": [e.to_dict() for e in fr.entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_freshness(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[FreshnessReport]:
    """If --freshness was requested, build and print the freshness report."""
    import sys
    if not getattr(args, "freshness", False):
        return None
    fr = build_freshness_report(
        report,
        major_threshold=args.freshness_major,
        minor_threshold=args.freshness_minor,
    )
    sink = out if out is not None else sys.stdout
    if args.freshness_format == "json":
        sink.write(_render_json(fr) + "\n")
    else:
        sink.write(_render_text(fr) + "\n")
    return fr
