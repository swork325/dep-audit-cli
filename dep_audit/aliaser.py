"""Package alias resolution: map known package aliases/renames to canonical names."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep

AliasMap = Dict[str, str]  # alias -> canonical

DEFAULT_ALIASES: AliasMap = {
    "pillow": "Pillow",
    "pil": "Pillow",
    "sklearn": "scikit-learn",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "dateutil": "python-dateutil",
}


def load_alias_map(path: Optional[Path] = None) -> AliasMap:
    """Load alias map from a JSON file, merging with built-in defaults."""
    merged: AliasMap = dict(DEFAULT_ALIASES)
    if path is None or not path.exists():
        return merged
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            merged.update({str(k).lower(): str(v) for k, v in data.items()})
    except (json.JSONDecodeError, OSError):
        pass
    return merged


def save_alias_map(alias_map: AliasMap, path: Path) -> None:
    """Persist an alias map to a JSON file."""
    path.write_text(json.dumps(alias_map, indent=2))


def resolve_alias(name: str, alias_map: AliasMap) -> str:
    """Return the canonical package name for *name*, or *name* unchanged."""
    return alias_map.get(name.lower(), name)


def _remap_dep(dep: ResolvedDep, alias_map: AliasMap) -> ResolvedDep:
    canonical = resolve_alias(dep.name, alias_map)
    if canonical == dep.name:
        return dep
    return ResolvedDep(
        name=canonical,
        current_version=dep.current_version,
        latest_version=dep.latest_version,
        vulnerabilities=dep.vulnerabilities,
    )


def alias_report(report: AuditReport, alias_map: AliasMap) -> AuditReport:
    """Return a new AuditReport with all dependency names resolved through *alias_map*."""
    new_files: List[FileAudit] = []
    for fa in report.files:
        remapped = [_remap_dep(d, alias_map) for d in fa.deps]
        new_files.append(FileAudit(path=fa.path, deps=remapped))
    return AuditReport(files=new_files)
