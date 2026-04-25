"""Lock-file consistency checker.

Compares resolved dependencies against a lock file (e.g. pip-compile output
or requirements.txt with pinned versions) and reports any packages that are
present in the audit but missing from the lock file, or whose pinned version
in the lock file differs from the latest available version.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.resolver import ResolvedDep


_PIN_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)==([^\s]+)")


@dataclass
class LockEntry:
    name: str
    locked_version: str


@dataclass
class LockInconsistency:
    name: str
    locked_version: Optional[str]   # None => missing from lock file
    latest_version: Optional[str]
    reason: str


@dataclass
class LockReport:
    lock_file: str
    inconsistencies: List[LockInconsistency] = field(default_factory=list)

    @property
    def is_consistent(self) -> bool:
        return len(self.inconsistencies) == 0

    @property
    def total(self) -> int:
        return len(self.inconsistencies)


def parse_lock_file(path: Path) -> Dict[str, str]:
    """Return {normalised_name: pinned_version} from a pinned requirements file."""
    result: Dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PIN_RE.match(line)
        if m:
            name = m.group(1).lower().replace("-", "_")
            result[name] = m.group(2)
    return result


def check_lock_consistency(
    deps: List[ResolvedDep],
    lock_path: Path,
) -> LockReport:
    """Compare *deps* against the pinned versions in *lock_path*."""
    locked = parse_lock_file(lock_path)
    report = LockReport(lock_file=str(lock_path))

    for dep in deps:
        key = dep.name.lower().replace("-", "_")
        pinned = locked.get(key)
        if pinned is None:
            report.inconsistencies.append(
                LockInconsistency(
                    name=dep.name,
                    locked_version=None,
                    latest_version=dep.latest_version,
                    reason="missing from lock file",
                )
            )
        elif dep.latest_version and pinned != dep.latest_version:
            report.inconsistencies.append(
                LockInconsistency(
                    name=dep.name,
                    locked_version=pinned,
                    latest_version=dep.latest_version,
                    reason=f"lock has {pinned}, latest is {dep.latest_version}",
                )
            )
    return report
