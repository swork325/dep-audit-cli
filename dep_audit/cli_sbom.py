"""CLI integration for SBOM generation."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_sbom import build_sbom, save_sbom


def add_sbom_args(parser: argparse.ArgumentParser) -> None:
    """Register --sbom and --sbom-output flags on *parser*."""
    parser.add_argument(
        "--sbom",
        action="store_true",
        default=False,
        help="Generate a CycloneDX SBOM document from the audit results.",
    )
    parser.add_argument(
        "--sbom-output",
        metavar="FILE",
        default=None,
        help="Write the SBOM JSON to FILE instead of stdout.",
    )
    parser.add_argument(
        "--sbom-format",
        choices=["json", "text"],
        default="json",
        help="Output format for the SBOM (default: json).",
    )


def _render_text(report: AuditReport) -> str:
    doc = build_sbom(report)
    lines = [f"SBOM  —  {doc.total} component(s)  [{doc.timestamp}]"]
    lines.append("-" * 60)
    for comp in doc.components:
        flags = []
        if comp.is_outdated:
            flags.append("outdated")
        if comp.is_vulnerable:
            flags.append("vulnerable")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        ver = comp.version or "unknown"
        lines.append(f"  {comp.name}=={ver}{flag_str}  ({comp.source_file})")
    return "\n".join(lines)


def maybe_render_sbom(
    args: argparse.Namespace,
    report: AuditReport,
    output=None,
) -> Optional[int]:
    """If --sbom is set, generate and emit the SBOM then return an exit code."""
    if not getattr(args, "sbom", False):
        return None

    out = output or sys.stdout
    fmt = getattr(args, "sbom_format", "json")
    dest = getattr(args, "sbom_output", None)

    if fmt == "text":
        text = _render_text(report)
        if dest:
            from pathlib import Path
            Path(dest).write_text(text, encoding="utf-8")
        else:
            print(text, file=out)
    else:
        doc = build_sbom(report)
        payload = json.dumps(doc.to_dict(), indent=2)
        if dest:
            save_sbom(doc, dest)
        else:
            print(payload, file=out)

    return 0
