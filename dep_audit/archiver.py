"""Archive audit reports to a timestamped JSONL log file."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dep_audit.auditor import AuditReport
from dep_audit.reporter import SummaryStats, compute_stats

DEFAULT_ARCHIVE = ".dep_audit_archive.jsonl"


def _report_entry(report: AuditReport, stats: SummaryStats) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_files": stats.total_files,
        "total_deps": stats.total_deps,
        "outdated": stats.outdated,
        "vulnerable": stats.vulnerable,
        "files": [
            {
                "path": fa.path,
                "deps": [
                    {
                        "name": d.name,
                        "current": d.current_version,
                        "latest": d.latest_version,
                        "outdated": d.outdated,
                        "vulns": [v.vuln_id for v in (d.vulnerabilities or [])],
                    }
                    for d in fa.deps
                ],
            }
            for fa in report.files
        ],
    }


def append_to_archive(report: AuditReport, archive_path: str = DEFAULT_ARCHIVE) -> Path:
    """Append a single audit snapshot to the JSONL archive file."""
    stats = compute_stats(report)
    entry = _report_entry(report, stats)
    path = Path(archive_path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return path


def load_archive(archive_path: str = DEFAULT_ARCHIVE) -> list[dict]:
    """Return all archived entries as a list of dicts."""
    path = Path(archive_path)
    if not path.exists():
        return []
    entries = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def prune_archive(archive_path: str = DEFAULT_ARCHIVE, keep: int = 30) -> int:
    """Keep only the *keep* most-recent entries. Returns number removed."""
    entries = load_archive(archive_path)
    if len(entries) <= keep:
        return 0
    removed = len(entries) - keep
    kept = entries[-keep:]
    path = Path(archive_path)
    with path.open("w", encoding="utf-8") as fh:
        for e in kept:
            fh.write(json.dumps(e) + "\n")
    return removed
