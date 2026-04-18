"""Support for .dep-audit-ignore files to suppress known issues."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from dep_audit.resolver import ResolvedDep

_DEFAULT_IGNORE_FILE = ".dep-audit-ignore"


def load_ignore_list(path: Optional[str] = None) -> set[str]:
    """Load ignored package names from a JSON ignore file.

    The file should contain a JSON array of package name strings, e.g.:
        ["requests", "boto3"]

    Returns an empty set if the file does not exist.
    """
    ignore_path = Path(path or _DEFAULT_IGNORE_FILE)
    if not ignore_path.exists():
        return set()
    try:
        data = json.loads(ignore_path.read_text())
        if not isinstance(data, list):
            return set()
        return {str(entry).lower() for entry in data if isinstance(entry, str)}
    except (json.JSONDecodeError, OSError):
        return set()


def save_ignore_list(packages: list[str], path: Optional[str] = None) -> None:
    """Persist a list of package names to the ignore file."""
    ignore_path = Path(path or _DEFAULT_IGNORE_FILE)
    ignore_path.write_text(json.dumps(sorted({p.lower() for p in packages}), indent=2))


def apply_ignore(deps: list[ResolvedDep], ignored: set[str]) -> list[ResolvedDep]:
    """Return only deps whose normalised name is NOT in the ignore set."""
    return [d for d in deps if d.name.lower() not in ignored]


def is_ignored(dep: ResolvedDep, ignored: set[str]) -> bool:
    """Return True if *dep* should be suppressed."""
    return dep.name.lower() in ignored
