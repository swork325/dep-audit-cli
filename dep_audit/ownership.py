"""Map packages to owning teams or individuals for triage routing."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_BUILTIN_OWNERS: Dict[str, str] = {}


def load_owner_map(path: Optional[str] = None) -> Dict[str, str]:
    """Return package -> owner mapping, merged with any user file."""
    owners: Dict[str, str] = dict(_BUILTIN_OWNERS)
    if path is None:
        return owners
    p = Path(path)
    if not p.exists():
        return owners
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            return owners
        owners.update({k.lower(): v for k, v in data.items() if isinstance(v, str)})
    except (json.JSONDecodeError, OSError):
        pass
    return owners


def save_owner_map(owner_map: Dict[str, str], path: str) -> None:
    """Persist owner map to *path* as JSON."""
    Path(path).write_text(json.dumps(owner_map, indent=2))


def owner_for_dep(dep: ResolvedDep, owner_map: Dict[str, str]) -> Optional[str]:
    """Return the owner string for *dep*, or None if unmapped."""
    return owner_map.get(dep.name.lower())


@dataclass
class OwnedDep:
    dep: ResolvedDep
    owner: Optional[str]


@dataclass
class OwnershipReport:
    entries: List[OwnedDep] = field(default_factory=list)

    def by_owner(self) -> Dict[str, List[ResolvedDep]]:
        result: Dict[str, List[ResolvedDep]] = {}
        for e in self.entries:
            key = e.owner or "(unassigned)"
            result.setdefault(key, []).append(e.dep)
        return result

    def unassigned(self) -> List[ResolvedDep]:
        return [e.dep for e in self.entries if e.owner is None]


def build_ownership_report(
    report: AuditReport, owner_map: Dict[str, str]
) -> OwnershipReport:
    """Attach owner information to every dep in *report*."""
    entries: List[OwnedDep] = []
    for fa in report.files:
        for dep in fa.deps:
            entries.append(OwnedDep(dep=dep, owner=owner_for_dep(dep, owner_map)))
    return OwnershipReport(entries=entries)
