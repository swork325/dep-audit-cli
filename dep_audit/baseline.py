"""Baseline snapshot: save and diff audit results to track new issues over time."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = ".dep-audit-baseline.json"


def _report_to_dict(report: Any) -> dict:
    """Serialize an AuditReport to a plain dict suitable for JSON storage."""
    files = {}
    for fa in report.file_audits:
        deps = []
        for d in fa.deps:
            deps.append({
                "name": d.name,
                "current": d.current_version,
                "latest": d.latest_version,
                "vulns": [v.vuln_id for v in (d.vulnerabilities or [])],
            })
        files[str(fa.path)] = deps
    return files


def save_baseline(report: Any, path: str | Path = DEFAULT_BASELINE) -> None:
    """Write the current audit state to a baseline file."""
    data = _report_to_dict(report)
    Path(path).write_text(json.dumps(data, indent=2))


def load_baseline(path: str | Path = DEFAULT_BASELINE) -> dict | None:
    """Load a previously saved baseline. Returns None if file does not exist."""
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def diff_baseline(report: Any, baseline: dict) -> dict[str, list[str]]:
    """Return new issues (outdated or vulnerable deps) not present in baseline.

    Returns a mapping of file path -> list of new dep names with issues.
    """
    current = _report_to_dict(report)
    new_issues: dict[str, list[str]] = {}

    for file_path, deps in current.items():
        baseline_names = {
            d["name"]
            for d in baseline.get(file_path, [])
            if d["latest"] and d["current"] != d["latest"] or d["vulns"]
        }
        for dep in deps:
            has_issue = (dep["latest"] and dep["current"] != dep["latest"]) or bool(dep["vulns"])
            if has_issue and dep["name"] not in baseline_names:
                new_issues.setdefault(file_path, []).append(dep["name"])

    return new_issues
