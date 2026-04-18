"""Track dependency health trends across multiple audit runs."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

from dep_audit.reporter import SummaryStats


@dataclass
class TrendEntry:
    timestamp: float
    total_deps: int
    outdated: int
    vulnerable: int
    issue_rate: float


@dataclass
class TrendHistory:
    entries: List[TrendEntry] = field(default_factory=list)

    def add(self, stats: SummaryStats) -> TrendEntry:
        entry = TrendEntry(
            timestamp=time.time(),
            total_deps=stats.total_deps,
            outdated=stats.outdated_deps,
            vulnerable=stats.vulnerable_deps,
            issue_rate=stats.issue_rate,
        )
        self.entries.append(entry)
        return entry

    def last(self) -> Optional[TrendEntry]:
        return self.entries[-1] if self.entries else None

    def since(self, cutoff: float) -> List[TrendEntry]:
        return [e for e in self.entries if e.timestamp >= cutoff]


def load_trend(path: Path) -> TrendHistory:
    if not path.exists():
        return TrendHistory()
    try:
        data = json.loads(path.read_text())
        entries = [TrendEntry(**e) for e in data.get("entries", [])]
        return TrendHistory(entries=entries)
    except Exception:
        return TrendHistory()


def save_trend(history: TrendHistory, path: Path) -> None:
    path.write_text(json.dumps({"entries": [asdict(e) for e in history.entries]}, indent=2))


def record_trend(stats: SummaryStats, path: Path) -> TrendEntry:
    history = load_trend(path)
    entry = history.add(stats)
    save_trend(history, path)
    return entry
