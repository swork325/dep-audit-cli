"""CLI helpers for the recommendation feature."""
from __future__ import annotations

import argparse
from typing import List

from dep_audit.recommender import Recommendation

ACTION_LABELS = {
    "upgrade": "⬆  Upgrade",
    "review_vulns": "🔍 Review vulns",
    "upgrade_and_review": "⬆🔍 Upgrade & review",
}


def add_recommend_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recommend",
        action="store_true",
        default=False,
        help="Print upgrade/review recommendations after the audit.",
    )
    parser.add_argument(
        "--recommend-action",
        choices=["upgrade", "review_vulns", "upgrade_and_review"],
        default=None,
        help="Filter recommendations by action type.",
    )


def filter_recommendations(
    recs: List[Recommendation], action: str | None
) -> List[Recommendation]:
    if action is None:
        return recs
    return [r for r in recs if r.action == action]


def render_recommendations(recs: List[Recommendation]) -> str:
    if not recs:
        return "No recommendations — all dependencies look good!\n"
    lines = ["Recommendations:", "-" * 40]
    for rec in recs:
        label = ACTION_LABELS.get(rec.action, rec.action)
        ver = f"{rec.current_version} -> {rec.latest_version}" if rec.latest_version else rec.current_version
        lines.append(f"  {label:30s}  {rec.package} ({ver})")
        lines.append(f"    {rec.reason}")
    return "\n".join(lines) + "\n"


def maybe_render_recommendations(args: argparse.Namespace, recs: List[Recommendation]) -> None:
    if not getattr(args, "recommend", False):
        return
    action_filter = getattr(args, "recommend_action", None)
    filtered = filter_recommendations(recs, action_filter)
    print(render_recommendations(filtered))
