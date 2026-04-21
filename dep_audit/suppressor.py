"""Suppressor: temporarily suppress known issues from audit reports."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

_DEFAULT_PATH = Path(".dep-audit-suppress.json")


def load_suppressions(path: Path = _DEFAULT_PATH) -> dict[str, str]:
    """Load suppression map {package_name: expiry_date_iso} from JSON file.

    Returns an empty dict if the file is missing or malformed.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {}
        return {k.lower(): v for k, v in data.items() if isinstance(v, str)}
    except (json.JSONDecodeError, OSError):
        return {}


def save_suppressions(
    suppressions: dict[str, str], path: Path = _DEFAULT_PATH
) -> None:
    """Persist suppression map to a JSON file."""
    path.write_text(json.dumps(suppressions, indent=2))


def is_suppressed(dep: ResolvedDep, suppressions: dict[str, str]) -> bool:
    """Return True if *dep* is suppressed and the suppression has not expired."""
    key = dep.name.lower()
    expiry_str = suppressions.get(key)
    if expiry_str is None:
        return False
    try:
        expiry = date.fromisoformat(expiry_str)
    except ValueError:
        return False
    return date.today() <= expiry


def apply_suppressions(
    report: AuditReport, suppressions: dict[str, str]
) -> AuditReport:
    """Return a new AuditReport with suppressed deps removed from each FileAudit."""
    filtered_files: list[FileAudit] = []
    for fa in report.files:
        kept = [d for d in fa.deps if not is_suppressed(d, suppressions)]
        filtered_files.append(FileAudit(path=fa.path, deps=kept))
    return AuditReport(files=filtered_files)


def add_suppression(
    name: str,
    expiry: date,
    path: Path = _DEFAULT_PATH,
) -> None:
    """Add or update a suppression entry and persist it."""
    suppressions = load_suppressions(path)
    suppressions[name.lower()] = expiry.isoformat()
    save_suppressions(suppressions, path)


def remove_suppression(name: str, path: Path = _DEFAULT_PATH) -> bool:
    """Remove a suppression entry. Returns True if it existed."""
    suppressions = load_suppressions(path)
    key = name.lower()
    if key not in suppressions:
        return False
    del suppressions[key]
    save_suppressions(suppressions, path)
    return True
