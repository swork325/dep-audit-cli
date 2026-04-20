"""CLI helpers for the pinboard feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.pinboard import PinboardReport, build_pinboard


def add_pinboard_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("pinboard")
    grp.add_argument(
        "--pinboard",
        action="store_true",
        default=False,
        help="Show pinning status for all dependencies.",
    )
    grp.add_argument(
        "--pinboard-format",
        choices=["text", "json"],
        default="text",
        dest="pinboard_format",
        help="Output format for pinboard report (default: text).",
    )
    grp.add_argument(
        "--pinboard-unpinned-only",
        action="store_true",
        default=False,
        dest="pinboard_unpinned_only",
        help="Only show unpinned dependencies in the pinboard report.",
    )


def _render_text(pb: PinboardReport, unpinned_only: bool) -> str:
    lines: list[str] = []
    lines.append(f"Pinboard  total={pb.total}  pin_rate={pb.pin_rate:.0%}")
    if not unpinned_only:
        lines.append(f"  Pinned ({len(pb.pinned)}):")
        for s in pb.pinned:
            lines.append(f"    {s.name} {s.current_version}")
    lines.append(f"  Unpinned ({len(pb.unpinned)}):")
    for s in pb.unpinned:
        hint = f" -> suggest {s.suggested_pin}" if s.suggested_pin else ""
        outdated = " [OUTDATED]" if s.is_outdated else ""
        lines.append(f"    {s.name} {s.current_version or '?'}{outdated}{hint}")
    return "\n".join(lines)


def _render_json(pb: PinboardReport, unpinned_only: bool) -> str:
    entries = pb.unpinned if unpinned_only else pb.pinned + pb.unpinned
    data = [
        {
            "name": s.name,
            "current_version": s.current_version,
            "latest_version": s.latest_version,
            "is_pinned": s.is_pinned,
            "is_outdated": s.is_outdated,
            "suggested_pin": s.suggested_pin,
        }
        for s in entries
    ]
    return json.dumps({"pin_rate": pb.pin_rate, "deps": data}, indent=2)


def maybe_render_pinboard(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[PinboardReport]:
    import sys
    if not getattr(args, "pinboard", False):
        return None
    pb = build_pinboard(report)
    unpinned_only = getattr(args, "pinboard_unpinned_only", False)
    fmt = getattr(args, "pinboard_format", "text")
    text = _render_json(pb, unpinned_only) if fmt == "json" else _render_text(pb, unpinned_only)
    sink = out or sys.stdout
    print(text, file=sink)
    return pb
