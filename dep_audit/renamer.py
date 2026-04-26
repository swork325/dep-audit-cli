"""Rename packages in a report using a canonical name map.

Some packages are published under multiple names (e.g. ``Pillow`` vs
``PIL``, ``scikit-learn`` vs ``sklearn``).  The renamer lets users
supply a JSON mapping of ``{alias: canonical}`` so that every
:class:`~dep_audit.resolver.ResolvedDep` in a report is normalised to
its canonical name before further processing.
"""
from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from typing import Dict, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

log = logging.getLogger(__name__)

_BUILTIN_RENAMES: Dict[str, str] = {
    "pil": "Pillow",
    "sklearn": "scikit-learn",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
}


def load_rename_map(path: Optional[Path] = None) -> Dict[str, str]:
    """Return a merge of built-in renames and any user-supplied JSON file.

    Keys are normalised to lower-case.  User entries take precedence over
    built-ins.
    """
    merged: Dict[str, str] = dict(_BUILTIN_RENAMES)
    if path is None or not path.exists():
        return merged
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            log.warning("rename map at %s is not a JSON object – ignoring", path)
            return merged
        merged.update({k.lower(): v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)})
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("could not load rename map from %s: %s", path, exc)
    return merged


def save_rename_map(rename_map: Dict[str, str], path: Path) -> None:
    """Persist *rename_map* to *path* as pretty-printed JSON."""
    path.write_text(json.dumps(rename_map, indent=2, sort_keys=True), encoding="utf-8")


def _rename_dep(dep: ResolvedDep, rename_map: Dict[str, str]) -> ResolvedDep:
    canonical = rename_map.get(dep.name.lower())
    if canonical is None or canonical == dep.name:
        return dep
    return replace(dep, name=canonical)


def rename_report(report: AuditReport, rename_map: Dict[str, str]) -> AuditReport:
    """Return a new :class:`AuditReport` with all dep names resolved to
    their canonical form according to *rename_map*."""
    new_files = [
        FileAudit(
            path=fa.path,
            deps=[_rename_dep(d, rename_map) for d in fa.deps],
        )
        for fa in report.files
    ]
    return AuditReport(files=new_files)
