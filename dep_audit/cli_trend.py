"""CLI helpers for trend tracking."""
from __future__ import annotations

import argparse
from pathlib import Path

from dep_audit.trend import load_trend, TrendHistory

DEFAULT_TREND_FILE = ".dep_audit_trend.json"


def add_trend_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trend-file",
        default=DEFAULT_TREND_FILE,
        metavar="PATH",
        help="JSON file used to persist trend history (default: %(default)s)",
    )
    parser.add_argument(
        "--show-trend",
        action="store_true",
        default=False,
        help="Print trend summary after audit",
    )
    parser.add_argument(
        "--trend-last",
        type=int,
        default=5,
        metavar="N",
        help="Number of recent trend entries to display (default: %(default)s)",
    )


def render_trend(history: TrendHistory, last_n: int = 5) -> str:
    entries = history.entries[-last_n:]
    if not entries:
        return "No trend data available."
    lines = ["Trend history (oldest → newest):",
             f"  {'Timestamp':<20} {'Deps':>6} {'Outdated':>9} {'Vuln':>6} {'Issue%':>8}"]
    for e in entries:
        import datetime
        ts = datetime.datetime.fromtimestamp(e.timestamp).strftime("%Y-%m-%d %H:%M")
        lines.append(f"  {ts:<20} {e.total_deps:>6} {e.outdated:>9} {e.vulnerable:>6} {e.issue_rate*100:>7.1f}%")
    return "\n".join(lines)


def maybe_record_and_show_trend(args: argparse.Namespace, stats) -> None:
    from dep_audit.trend import record_trend
    path = Path(args.trend_file)
    record_trend(stats, path)
    if args.show_trend:
        history = load_trend(path)
        print(render_trend(history, last_n=args.trend_last))
