"""CLI integration for the package activity auditor."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_activity import ActivityReport, build_activity_report


def add_activity_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("activity")
    grp.add_argument(
        "--show-activity",
        action="store_true",
        default=False,
        help="Show package release-activity report.",
    )
    grp.add_argument(
        "--activity-threshold",
        type=int,
        default=365,
        metavar="DAYS",
        help="Days without a release before a package is considered inactive (default: 365).",
    )
    grp.add_argument(
        "--activity-format",
        choices=["text", "json"],
        default="text",
        help="Output format for the activity report.",
    )
    grp.add_argument(
        "--activity-inactive-only",
        action="store_true",
        default=False,
        help="Only show inactive packages.",
    )


def _render_text(activity: ActivityReport, inactive_only: bool) -> None:
    entries = activity.inactive_only() if inactive_only else activity.entries
    print(f"\n=== Activity Report ({activity.inactive_count()}/{activity.total()} inactive) ===")
    if not entries:
        print("  No entries to display.")
        return
    for e in entries:
        status = "INACTIVE" if e.is_inactive else "active"
        age = f"{e.days_since_release}d" if e.days_since_release is not None else "unknown"
        print(f"  {e.name}=={e.version}  last_release={age}  [{status}]")


def _render_json(activity: ActivityReport, inactive_only: bool) -> None:
    entries = activity.inactive_only() if inactive_only else activity.entries
    print(json.dumps([e.to_dict() for e in entries], indent=2))


def maybe_render_activity(
    args: argparse.Namespace,
    report: AuditReport,
    session=None,
) -> None:
    if not getattr(args, "show_activity", False):
        return
    threshold = getattr(args, "activity_threshold", 365)
    fmt = getattr(args, "activity_format", "text")
    inactive_only = getattr(args, "activity_inactive_only", False)
    activity = build_activity_report(report, threshold_days=threshold, session=session)
    if fmt == "json":
        _render_json(activity, inactive_only)
    else:
        _render_text(activity, inactive_only)
