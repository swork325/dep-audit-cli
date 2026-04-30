"""CLI integration for the maturity report feature."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.auditor_maturity import MaturityReport, build_maturity_report


def add_maturity_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("maturity")
    group.add_argument(
        "--maturity",
        action="store_true",
        default=False,
        help="Show dependency maturity assessment.",
    )
    group.add_argument(
        "--maturity-format",
        choices=["text", "json"],
        default="text",
        help="Output format for maturity report (default: text).",
    )
    group.add_argument(
        "--maturity-immature-only",
        action="store_true",
        default=False,
        help="Only show immature dependencies.",
    )


def _render_text(mat_report: MaturityReport, immature_only: bool) -> str:
    lines = ["=== Maturity Report ==="]
    entries = (
        [e for e in mat_report.entries if not e.is_mature]
        if immature_only
        else mat_report.entries
    )
    if not entries:
        lines.append("  (no entries to display)")
        return "\n".join(lines)
    for e in entries:
        status = "MATURE" if e.is_mature else "IMMATURE"
        lines.append(f"  {e.name} {e.current_version}  [{status}]  {e.reason}")
    lines.append(f"\nTotal: {mat_report.total}  Immature: {mat_report.immature_count}")
    return "\n".join(lines)


def _render_json(mat_report: MaturityReport, immature_only: bool) -> str:
    entries = (
        [e for e in mat_report.entries if not e.is_mature]
        if immature_only
        else mat_report.entries
    )
    payload = {
        "total": mat_report.total,
        "immature_count": mat_report.immature_count,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_maturity(
    args: argparse.Namespace,
    report: AuditReport,
    session: Optional[requests.Session] = None,
    out=None,
) -> None:
    if not getattr(args, "maturity", False):
        return
    if out is None:
        out = sys.stdout
    mat_report = build_maturity_report(report, session=session)
    fmt = getattr(args, "maturity_format", "text")
    immature_only = getattr(args, "maturity_immature_only", False)
    if fmt == "json":
        out.write(_render_json(mat_report, immature_only) + "\n")
    else:
        out.write(_render_text(mat_report, immature_only) + "\n")
