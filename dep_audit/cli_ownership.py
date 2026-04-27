"""CLI integration for the ownership feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.ownership import build_ownership_report, load_owner_map


def add_ownership_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("ownership")
    grp.add_argument(
        "--owner-map",
        metavar="FILE",
        default=None,
        help="JSON file mapping package names to owner strings",
    )
    grp.add_argument(
        "--show-ownership",
        action="store_true",
        default=False,
        help="Print ownership breakdown after the main report",
    )
    grp.add_argument(
        "--ownership-format",
        choices=["text", "json"],
        default="text",
        help="Output format for ownership report (default: text)",
    )


def _render_text(report: AuditReport, owner_map_path: Optional[str]) -> None:
    owner_map = load_owner_map(owner_map_path)
    ow = build_ownership_report(report, owner_map)
    by_owner = ow.by_owner()
    print("\n=== Ownership Breakdown ===")
    for owner, deps in sorted(by_owner.items()):
        print(f"  {owner}: {', '.join(d.name for d in deps)}")
    unassigned = ow.unassigned()
    print(f"  Unassigned: {len(unassigned)} package(s)")


def _render_json(report: AuditReport, owner_map_path: Optional[str]) -> None:
    owner_map = load_owner_map(owner_map_path)
    ow = build_ownership_report(report, owner_map)
    out = {
        owner: [d.name for d in deps]
        for owner, deps in ow.by_owner().items()
    }
    print(json.dumps(out, indent=2))


def maybe_render_ownership(
    args: argparse.Namespace, report: AuditReport
) -> None:
    if not getattr(args, "show_ownership", False):
        return
    fmt = getattr(args, "ownership_format", "text")
    path = getattr(args, "owner_map", None)
    if fmt == "json":
        _render_json(report, path)
    else:
        _render_text(report, path)
