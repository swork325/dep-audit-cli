"""Timeline: track when each dependency was first and last seen across audit runs."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport

_DEFAULT_TIMELINE_FILE = ".dep_audit_timeline.json"
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass
class TimelineEntry:
    package: str
    first_seen: str
    last_seen: str
    seen_count: int = 1
    was_outdated: bool = False
    was_vulnerable: bool = False

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": self.seen_count,
            "was_outdated": self.was_outdated,
            "was_vulnerable": self.was_vulnerable,
        }


@dataclass
class Timeline:
    entries: Dict[str, TimelineEntry] = field(default_factory=dict)

    def total(self) -> int:
        return len(self.entries)

    def ever_vulnerable(self) -> List[TimelineEntry]:
        return [e for e in self.entries.values() if e.was_vulnerable]

    def ever_outdated(self) -> List[TimelineEntry]:
        return [e for e in self.entries.values() if e.was_outdated]


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def update_timeline(report: AuditReport, path: Path = Path(_DEFAULT_TIMELINE_FILE)) -> Timeline:
    """Merge current report into the persisted timeline and save."""
    timeline = load_timeline(path)
    now = _now_utc()

    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            outdated = dep.latest is not None and dep.latest != dep.version
            vulnerable = bool(dep.vulns)
            if key in timeline.entries:
                entry = timeline.entries[key]
                entry.last_seen = now
                entry.seen_count += 1
                entry.was_outdated = entry.was_outdated or outdated
                entry.was_vulnerable = entry.was_vulnerable or vulnerable
            else:
                timeline.entries[key] = TimelineEntry(
                    package=dep.name,
                    first_seen=now,
                    last_seen=now,
                    seen_count=1,
                    was_outdated=outdated,
                    was_vulnerable=vulnerable,
                )

    save_timeline(timeline, path)
    return timeline


def save_timeline(timeline: Timeline, path: Path = Path(_DEFAULT_TIMELINE_FILE)) -> None:
    data = {k: v.to_dict() for k, v in timeline.entries.items()}
    path.write_text(json.dumps(data, indent=2))


def load_timeline(path: Path = Path(_DEFAULT_TIMELINE_FILE)) -> Timeline:
    if not path.exists():
        return Timeline()
    try:
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict):
            return Timeline()
        entries = {k: TimelineEntry(**v) for k, v in raw.items()}
        return Timeline(entries=entries)
    except Exception:
        return Timeline()
