"""CLI integration for badge generation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dep_audit.auditor import AuditReport
from dep_audit.auditor_badge import build_badge


def add_badge_args(parser: argparse.ArgumentParser) -> None:
    """Attach badge-related flags to *parser*."""
    grp = parser.add_argument_group("badge")
    grp.add_argument(
        "--badge",
        action="store_true",
        default=False,
        help="Print a shields.io-compatible JSON badge to stdout.",
    )
    grp.add_argument(
        "--badge-label",
        default="dependencies",
        metavar="LABEL",
        help="Custom label for the badge (default: 'dependencies').",
    )
    grp.add_argument(
        "--badge-out",
        default=None,
        metavar="FILE",
        help="Write badge JSON to FILE instead of stdout.",
    )


def maybe_render_badge(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> None:
    """If --badge was requested, render and output badge JSON."""
    if not getattr(args, "badge", False):
        return

    badge = build_badge(report, label=args.badge_label)
    payload = json.dumps(badge.to_dict(), indent=2)

    dest = getattr(args, "badge_out", None)
    if dest:
        Path(dest).write_text(payload + "\n", encoding="utf-8")
    else:
        stream = out or sys.stdout
        stream.write(payload + "\n")
