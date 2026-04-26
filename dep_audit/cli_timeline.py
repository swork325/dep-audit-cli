"""CLI integration for the timeline feature."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from dep_audit.auditor import AuditReport
from dep_audit.timeline import Timeline, load_timeline, update_timeline

_DEFAULT_FILE = ".dep_audit_timeline.json"


def add_timeline_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("timeline")
    g.add_argument(
        "--timeline",
        action="store_true",
        default=False,
        help="Show the dependency timeline (first/last seen, counts).",
    )
    g.add_argument(
        "--timeline-file",
        default=_DEFAULT_FILE,
        metavar="PATH",
        help="Path to the timeline JSON file (default: %(default)s).",
    )
    g.add_argument(
        "--timeline-format",
        choices=["text", "json"],
        default="text",
        help="Output format for the timeline (default: text).",
    )
    g.add_argument(
        "--timeline-only-flagged",
        action="store_true",
        default=False,
        help="Limit timeline output to packages that were ever outdated or vulnerable.",
    )


def _render_text(timeline: Timeline, only_flagged: bool) -> str:
    entries = list(timeline.entries.values())
    if only_flagged:
        entries = [e for e in entries if e.was_outdated or e.was_vulnerable]
    if not entries:
        return "timeline: no entries to display.\n"
    lines = [f"{'Package':<30} {'First Seen':<22} {'Last Seen':<22} {'Seen':>5} {'Outdated':>9} {'Vuln':>6}"]
    lines.append("-" * 100)
    for e in sorted(entries, key=lambda x: x.package.lower()):
        lines.append(
            f"{e.package:<30} {e.first_seen:<22} {e.last_seen:<22} "
            f"{e.seen_count:>5} {'yes' if e.was_outdated else 'no':>9} {'yes' if e.was_vulnerable else 'no':>6}"
        )
    return "\n".join(lines) + "\n"


def _render_json(timeline: Timeline, only_flagged: bool) -> str:
    entries = list(timeline.entries.values())
    if only_flagged:
        entries = [e for e in entries if e.was_outdated or e.was_vulnerable]
    return json.dumps([e.to_dict() for e in entries], indent=2)


def maybe_record_and_show_timeline(
    args: argparse.Namespace, report: AuditReport
) -> None:
    timeline_path = Path(args.timeline_file)
    update_timeline(report, timeline_path)

    if not args.timeline:
        return

    timeline = load_timeline(timeline_path)
    only_flagged = args.timeline_only_flagged
    if args.timeline_format == "json":
        print(_render_json(timeline, only_flagged))
    else:
        print(_render_text(timeline, only_flagged))
