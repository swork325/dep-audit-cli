"""CLI helpers for the scorer-trend feature."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from dep_audit.scorer import ScoredReport
from dep_audit.scorer_trend import ScoreTrendReport, compare_scores, scores_to_dict

_DEFAULT_SNAPSHOT = ".dep_audit_score_snapshot.json"


def add_scorer_trend_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("scorer-trend")
    grp.add_argument(
        "--score-trend",
        action="store_true",
        default=False,
        help="Show packages whose risk score has risen since the last run.",
    )
    grp.add_argument(
        "--score-snapshot",
        metavar="FILE",
        default=_DEFAULT_SNAPSHOT,
        help=f"Path to score snapshot file (default: {_DEFAULT_SNAPSHOT}).",
    )
    grp.add_argument(
        "--score-trend-top",
        metavar="N",
        type=int,
        default=5,
        help="Number of top rising packages to display (default: 5).",
    )


def _load_snapshot(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_snapshot(scores: dict, path: str) -> None:
    try:
        Path(path).write_text(json.dumps(scores, indent=2))
    except OSError:
        pass


def maybe_render_score_trend(
    args: argparse.Namespace,
    scored: Optional[ScoredReport],
) -> None:
    """If --score-trend is set, compare against the last snapshot and print."""
    if not getattr(args, "score_trend", False) or scored is None:
        return

    snapshot_path: str = getattr(args, "score_snapshot", _DEFAULT_SNAPSHOT)
    top_n: int = getattr(args, "score_trend_top", 5)

    previous = _load_snapshot(snapshot_path)
    trend: ScoreTrendReport = compare_scores(scored, previous)

    # Persist updated snapshot
    _save_snapshot(scores_to_dict(scored), snapshot_path)

    print("\n=== Score Trend ===")
    rising = trend.top_rising(top_n)
    if not rising:
        print("  No packages with rising risk scores.")
    else:
        print(f"  {'Package':<30} {'Prev':>6} {'Now':>6} {'Delta':>6}")
        print("  " + "-" * 52)
        for r in rising:
            print(f"  {r.package:<30} {r.previous_score:>6.1f} {r.current_score:>6.1f} {r.delta:>+6.1f}")

    print(f"  Improving : {len(trend.improving)}")
    print(f"  Stable    : {len(trend.stable)}")
    print(f"  Rising    : {trend.total_rising}")
