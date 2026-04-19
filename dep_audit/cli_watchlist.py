"""CLI helpers for watchlist integration."""
from __future__ import annotations

import argparse
from typing import List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.watchlist import (
    DEFAULT_WATCHLIST_FILE,
    filter_by_watchlist,
    load_watchlist,
)


def add_watchlist_args(parser: argparse.ArgumentParser) -> None:
    """Attach watchlist flags to an existing parser."""
    parser.add_argument(
        "--watchlist",
        metavar="FILE",
        default=None,
        help="Path to watchlist JSON file; only show watched packages.",
    )
    parser.add_argument(
        "--show-watched-only",
        action="store_true",
        default=False,
        help="Filter output to watchlisted packages only.",
    )


def maybe_filter_by_watchlist(
    report: AuditReport, args: argparse.Namespace
) -> AuditReport:
    """If --show-watched-only is set, filter the report."""
    if not getattr(args, "show_watched_only", False):
        return report
    wl_path = getattr(args, "watchlist", None) or DEFAULT_WATCHLIST_FILE
    watchlist = load_watchlist(wl_path)
    if not watchlist:
        return report
    return filter_by_watchlist(report, watchlist)


def print_watchlist_summary(report: AuditReport, watchlist: List[str]) -> None:
    """Print a short summary of watched packages found in the report."""
    found = [
        dep
        for fa in report.files
        for dep in fa.deps
        if dep.name.lower() in watchlist
    ]
    if not found:
        print("No watched packages found.")
        return
    print(f"Watched packages ({len(found)} found):")
    for dep in found:
        status = "outdated" if dep.latest and dep.installed != dep.latest else "ok"
        print(f"  {dep.name} {dep.installed} [{status}]")
