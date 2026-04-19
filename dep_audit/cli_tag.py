"""CLI helpers for tag-based filtering and display."""
from __future__ import annotations

import argparse
from typing import Optional

from dep_audit.tagger import load_tag_map, tag_report, filter_by_tag
from dep_audit.auditor import AuditReport

DEFAULT_TAG_FILE = ".dep_tags.json"


def add_tag_args(parser: argparse.ArgumentParser) -> None:
    """Attach tag-related arguments to an existing parser."""
    parser.add_argument(
        "--tag-file",
        default=DEFAULT_TAG_FILE,
        metavar="PATH",
        help="JSON file mapping package names to tags (default: .dep_tags.json)",
    )
    parser.add_argument(
        "--filter-tag",
        default=None,
        metavar="TAG",
        help="Only show dependencies that carry this tag",
    )
    parser.add_argument(
        "--list-tags",
        action="store_true",
        default=False,
        help="Print a summary of tags and their dep counts, then exit",
    )


def apply_tag_filter(report: AuditReport, args: argparse.Namespace) -> AuditReport:
    """Return a (possibly filtered) report based on --filter-tag."""
    if not args.filter_tag:
        return report
    tag_map = load_tag_map(args.tag_file)
    return filter_by_tag(report, args.filter_tag, tag_map)


def maybe_print_tags(report: AuditReport, args: argparse.Namespace) -> bool:
    """If --list-tags was requested, print tag summary and return True; else False."""
    if not args.list_tags:
        return False
    tag_map = load_tag_map(args.tag_file)
    grouped = tag_report(report, tag_map)
    if not grouped:
        print("No tags defined or no matching dependencies found.")
    else:
        for tag, deps in sorted(grouped.items()):
            names = ", ".join(sorted({d.name for d in deps}))
            print(f"  [{tag}] ({len(deps)} dep(s)): {names}")
    return True
