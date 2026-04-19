"""Snapshot the current audit report state for point-in-time comparisons."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.reporter import SummaryStats, compute_stats


def _report_snapshot(report: AuditReport) -> dict:
    files = []
    for fa in report.files:
        deps = []
        for d in fa.deps:
            deps.append({
                "name": d.name,
                "current": d.current_version,
                "latest": d.latest_version,
                "outdated": d.outdated,
                "vulns": [v.id for v in (d.vulns or [])],
            })
        files.append({"path": fa.path, "deps": deps})
    stats = compute_stats(report)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_files": stats.total_files,
            "total_deps": stats.total_deps,
            "outdated": stats.outdated,
            "vulnerable": stats.vulnerable,
            "issue_rate": round(stats.issue_rate, 4),
        },
        "files": files,
    }


def save_snapshot(report: AuditReport, path: str) -> None:
    """Persist a snapshot of *report* to *path* as JSON."""
    data = _report_snapshot(report)
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def load_snapshot(path: str) -> Optional[dict]:
    """Load a previously saved snapshot; returns None if file is absent."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def snapshot_diff(old: dict, new: dict) -> dict:
    """Return a high-level diff between two snapshot dicts."""
    old_stats = old.get("stats", {})
    new_stats = new.get("stats", {})

    def _pkg_set(snapshot: dict) -> set:
        return {
            (f["path"], d["name"])
            for f in snapshot.get("files", [])
            for d in f.get("deps", [])
        }

    old_pkgs = _pkg_set(old)
    new_pkgs = _pkg_set(new)
    return {
        "added": sorted(new_pkgs - old_pkgs),
        "removed": sorted(old_pkgs - new_pkgs),
        "outdated_delta": new_stats.get("outdated", 0) - old_stats.get("outdated", 0),
        "vulnerable_delta": new_stats.get("vulnerable", 0) - old_stats.get("vulnerable", 0),
    }
