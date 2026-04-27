"""Combine score history with trend data to surface packages whose risk
is increasing over time."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.scorer import ScoredDep, ScoredReport
from dep_audit.trend import TrendHistory


@dataclass
class ScoredTrendEntry:
    """A single package's score at a recorded point in time."""

    package: str
    score: float
    timestamp: str  # ISO-8601


@dataclass
class RisingPackage:
    """Package whose score has increased (worsened) compared to a baseline."""

    package: str
    previous_score: float
    current_score: float

    @property
    def delta(self) -> float:
        return round(self.current_score - self.previous_score, 2)


@dataclass
class ScoreTrendReport:
    rising: List[RisingPackage] = field(default_factory=list)
    stable: List[str] = field(default_factory=list)
    improving: List[str] = field(default_factory=list)

    @property
    def total_rising(self) -> int:
        return len(self.rising)

    def top_rising(self, n: int = 5) -> List[RisingPackage]:
        return sorted(self.rising, key=lambda r: r.delta, reverse=True)[:n]


def record_scores(report: ScoredReport, history: TrendHistory) -> None:
    """Persist current scores into the trend history (one entry per run)."""
    from dep_audit.trend import TrendEntry
    from dep_audit.reporter import SummaryStats
    import datetime

    # We piggy-back on TrendHistory by storing a synthetic SummaryStats whose
    # total_deps encodes the aggregate score so existing persistence works.
    # Individual package scores are stored via history.add with a custom attr.
    now = datetime.datetime.utcnow().isoformat()
    for sd in report.deps:
        entry = ScoredTrendEntry(package=sd.dep.name, score=sd.score, timestamp=now)
        if not hasattr(history, "_score_log"):
            history._score_log: List[ScoredTrendEntry] = []
        history._score_log.append(entry)  # type: ignore[attr-defined]


def compare_scores(
    current: ScoredReport,
    previous: Dict[str, float],
) -> ScoreTrendReport:
    """Compare current scores against a previous snapshot dict {name: score}."""
    result = ScoreTrendReport()
    current_map: Dict[str, float] = {sd.dep.name: sd.score for sd in current.deps}

    for name, cur_score in current_map.items():
        prev_score = previous.get(name)
        if prev_score is None:
            result.stable.append(name)
            continue
        if cur_score > prev_score:
            result.rising.append(
                RisingPackage(package=name, previous_score=prev_score, current_score=cur_score)
            )
        elif cur_score < prev_score:
            result.improving.append(name)
        else:
            result.stable.append(name)

    return result


def scores_to_dict(report: ScoredReport) -> Dict[str, float]:
    """Flatten a ScoredReport into {package_name: score} for persistence."""
    return {sd.dep.name: sd.score for sd in report.deps}
