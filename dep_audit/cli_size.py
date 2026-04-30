"""CLI integration for the dependency size auditor."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_size import SizeReport, build_size_report


def add_size_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("size")
    grp.add_argument(
        "--show-size",
        action="store_true",
        default=False,
        help="Show package size information from PyPI.",
    )
    grp.add_argument(
        "--size-format",
        choices=["text", "json"],
        default="text",
        help="Output format for size report (default: text).",
    )
    grp.add_argument(
        "--size-large-only",
        action="store_true",
        default=False,
        help="Only show packages that exceed the large-size threshold.",
    )


def _render_text(size_report: SizeReport, large_only: bool) -> None:
    entries = [e for e in size_report.entries if e.is_large] if large_only else size_report.entries
    if not entries:
        print("No size data available.")
        return
    print(f"\n{'Package':<30} {'Version':<15} {'Size':>12}  Large")
    print("-" * 65)
    for e in sorted(entries, key=lambda x: (x.size_bytes or 0), reverse=True):
        size_str = f"{e.size_bytes:,}" if e.size_bytes is not None else "unknown"
        flag = "YES" if e.is_large else ""
        print(f"{e.name:<30} {e.version:<15} {size_str:>12}  {flag}")
    print(f"\n{size_report.large_count}/{size_report.total} packages exceed the size threshold.")


def _render_json(size_report: SizeReport, large_only: bool) -> None:
    entries = [e for e in size_report.entries if e.is_large] if large_only else size_report.entries
    print(json.dumps([e.to_dict() for e in entries], indent=2))


def maybe_render_size(
    args: argparse.Namespace,
    report: AuditReport,
    session=None,
) -> None:
    if not getattr(args, "show_size", False):
        return
    size_report = build_size_report(report, session=session)
    large_only = getattr(args, "size_large_only", False)
    fmt = getattr(args, "size_format", "text")
    if fmt == "json":
        _render_json(size_report, large_only)
    else:
        _render_text(size_report, large_only)
