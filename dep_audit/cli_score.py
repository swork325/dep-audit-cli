"""CLI helpers for the risk scorer."""
from __future__ import annotations

import argparse
from typing import Optional

from dep_audit.scorer import ScoredReport


def add_score_args(parser: argparse.ArgumentParser) -> None:
    """Attach score-related flags to *parser*."""
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="Show the N highest-risk dependencies.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        metavar="SCORE",
        help="Only show dependencies with risk score >= SCORE (default: 0).",
    )


def render_scores(scored: ScoredReport, top: Optional[int], min_score: int) -> str:
    """Return a human-readable string summarising risk scores."""
    deps = scored.above(min_score)
    if top is not None:
        deps = sorted(deps, key=lambda s: s.score, reverse=True)[:top]
    else:
        deps = sorted(deps, key=lambda s: s.score, reverse=True)

    if not deps:
        return "No dependencies meet the score threshold.\n"

    lines = ["Risk Scores", "-" * 40]
    for sd in deps:
        reasons = ", ".join(sd.reasons) if sd.reasons else "none"
        lines.append(f"{sd.dep.name:<30} score={sd.score:>3}  reasons=[{reasons}]")
    return "\n".join(lines) + "\n"


def maybe_render_scores(
    args: argparse.Namespace, scored: ScoredReport
) -> Optional[str]:
    """Return rendered score output when the user requested it, else None."""
    if getattr(args, "top", None) is not None or getattr(args, "min_score", 0) > 0:
        return render_scores(scored, top=args.top, min_score=args.min_score)
    return None
