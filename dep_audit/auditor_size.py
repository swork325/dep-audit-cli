"""Audit the installed size of each dependency via PyPI metadata."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport

_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_LARGE_BYTES = 10 * 1024 * 1024  # 10 MB


@dataclass
class SizeEntry:
    name: str
    version: str
    size_bytes: Optional[int]
    is_large: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "size_bytes": self.size_bytes,
            "is_large": self.is_large,
        }


@dataclass
class SizeReport:
    entries: List[SizeEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def large_count(self) -> int:
        return sum(1 for e in self.entries if e.is_large)

    def find(self, name: str) -> Optional[SizeEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None


def _fetch_size(name: str, version: str, session: requests.Session) -> Optional[int]:
    try:
        resp = session.get(_PYPI_URL.format(name=name), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {}).get(version, [])
        total = sum(f.get("size", 0) for f in releases if isinstance(f, dict))
        return total if total > 0 else None
    except Exception:
        return None


def _assess(name: str, version: str, session: requests.Session) -> SizeEntry:
    size = _fetch_size(name, version, session)
    return SizeEntry(
        name=name,
        version=version,
        size_bytes=size,
        is_large=(size is not None and size >= _LARGE_BYTES),
    )


def build_size_report(report: AuditReport, session: Optional[requests.Session] = None) -> SizeReport:
    if session is None:
        session = requests.Session()
    seen: dict[str, str] = {}
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower().replace("-", "_")
            if key not in seen:
                seen[key] = dep.latest or dep.current
    entries = [_assess(name, ver, session) for name, ver in seen.items()]
    return SizeReport(entries=entries)
