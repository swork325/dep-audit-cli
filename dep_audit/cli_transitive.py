"""CLI integration for the transitive dependency report."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_transitive import TransitiveReport, build_transitive_report


def add_transitive_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("transitive dependencies")
    grp.add_argument(
        "--transitive",
        action="store_true",
        default=False,
        help="Show transitive (indirect) dependency breakdown.",
    )
    grp.add_argument(
        "--transitive-format",
        choices=["text", "json"],
        default="text",
        dest="transitive_format",
        help="Output format for the transitive report (default: text).",
    )
    grp.add_argument(
        "--indirect-only",
        action="store_true",
        default=False,
        dest="indirect_only",
        help="Only show packages that are purely indirect dependencies.",
    )


def _render_text(tr: TransitiveReport, indirect_only: bool = False) -> str:
    lines = ["Transitive Dependency Report", "=" * 30]
    entries = tr.indirect_only() if indirect_only else tr.entries
    if not entries:
        lines.append("No dependencies found.")
        return "\n".join(lines)
    lines.append(f"Total: {tr.total}  Direct: {tr.direct_count}  Indirect: {tr.indirect_count}")
    lines.append("")
    for e in sorted(entries, key=lambda x: x.name.lower()):
        tag = "direct" if e.is_direct else "indirect"
        via = f"  (via: {', '.join(e.required_by)})" if e.required_by else ""
        version = e.current_version or "unpinned"
        lines.append(f"  {e.name}=={version}  [{tag}]{via}")
    return "\n".join(lines)


def _render_json(tr: TransitiveReport, indirect_only: bool = False) -> str:
    entries = tr.indirect_only() if indirect_only else tr.entries
    payload = {
        "total": tr.total,
        "direct_count": tr.direct_count,
        "indirect_count": tr.indirect_count,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_transitive(
    args: argparse.Namespace,
    report: AuditReport,
    dep_tree: Optional[dict] = None,
) -> Optional[str]:
    if not getattr(args, "transitive", False):
        return None
    tr = build_transitive_report(report, dep_tree=dep_tree)
    indirect_only = getattr(args, "indirect_only", False)
    fmt = getattr(args, "transitive_format", "text")
    if fmt == "json":
        return _render_json(tr, indirect_only=indirect_only)
    return _render_text(tr, indirect_only=indirect_only)
