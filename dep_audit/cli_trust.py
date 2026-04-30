"""CLI integration for the dependency trust report."""
from __future__ import annotations

import argparse
import json
from typing import Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.auditor_trust import TrustReport, build_trust_report


def add_trust_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trust",
        action="store_true",
        default=False,
        help="Show dependency trust assessment.",
    )
    parser.add_argument(
        "--trust-format",
        choices=["text", "json"],
        default="text",
        help="Output format for trust report (default: text).",
    )
    parser.add_argument(
        "--trust-only-untrusted",
        action="store_true",
        default=False,
        help="Only show untrusted dependencies.",
    )


def _render_text(trust_report: TrustReport, only_untrusted: bool) -> str:
    lines = ["=== Dependency Trust Report ==="]
    entries = trust_report.entries
    if only_untrusted:
        entries = [e for e in entries if not e.trusted]
    if not entries:
        lines.append("  All dependencies meet trust thresholds.")
        return "\n".join(lines)
    for e in entries:
        status = "TRUSTED" if e.trusted else "UNTRUSTED"
        lines.append(f"  [{status}] {e.name}=={e.version}  releases={e.release_count}  reason={e.reason}")
    lines.append(f"\nTotal: {trust_report.total()}  Untrusted: {trust_report.untrusted_count()}")
    return "\n".join(lines)


def _render_json(trust_report: TrustReport, only_untrusted: bool) -> str:
    entries = trust_report.entries
    if only_untrusted:
        entries = [e for e in entries if not e.trusted]
    payload = {
        "total": trust_report.total(),
        "untrusted_count": trust_report.untrusted_count(),
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_trust(
    args: argparse.Namespace,
    report: AuditReport,
    session: Optional[requests.Session] = None,
) -> None:
    if not getattr(args, "trust", False):
        return
    trust_report = build_trust_report(report, session=session)
    only_untrusted = getattr(args, "trust_only_untrusted", False)
    fmt = getattr(args, "trust_format", "text")
    if fmt == "json":
        print(_render_json(trust_report, only_untrusted))
    else:
        print(_render_text(trust_report, only_untrusted))
