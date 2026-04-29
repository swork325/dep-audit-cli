"""CLI integration for provenance checking."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_provenance import ProvenanceReport, check_provenance


def add_provenance_args(parser: argparse.ArgumentParser) -> None:
    """Attach provenance-related flags to an existing parser."""
    parser.add_argument(
        "--provenance",
        action="store_true",
        default=False,
        help="Check that each dependency originates from the expected source.",
    )
    parser.add_argument(
        "--provenance-source",
        default="pypi.org",
        metavar="SOURCE",
        help="Expected source domain/prefix for packages (default: pypi.org).",
    )
    parser.add_argument(
        "--provenance-format",
        choices=["text", "json"],
        default="text",
        help="Output format for provenance report.",
    )


def _render_text(prov: ProvenanceReport) -> str:
    lines = ["Provenance Report", "=" * 40]
    lines.append(f"Total packages checked : {prov.total}")
    lines.append(f"Unverified             : {prov.unverified_count}")
    if prov.unverified_count:
        lines.append("\nUnverified packages:")
        for e in prov.unverified():
            src = e.actual_url or "(no URL found)"
            lines.append(f"  {e.name} {e.version or ''} -> {src}")
    else:
        lines.append("\nAll packages verified.")
    return "\n".join(lines)


def _render_json(prov: ProvenanceReport) -> str:
    return json.dumps(
        {
            "total": prov.total,
            "unverified_count": prov.unverified_count,
            "entries": [e.to_dict() for e in prov.entries],
        },
        indent=2,
    )


def maybe_render_provenance(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[ProvenanceReport]:
    """Run provenance check and print results if --provenance flag is set."""
    if not getattr(args, "provenance", False):
        return None
    out = out or sys.stdout
    source = getattr(args, "provenance_source", "pypi.org")
    fmt = getattr(args, "provenance_format", "text")
    prov = check_provenance(report, expected_source=source)
    if fmt == "json":
        out.write(_render_json(prov) + "\n")
    else:
        out.write(_render_text(prov) + "\n")
    return prov
