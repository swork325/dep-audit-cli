"""Detect deprecated packages by inspecting PyPI classifiers and metadata."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import requests

from dep_audit.resolver import ResolvedDep, _normalize

_DEPRECATED_CLASSIFIERS = {
    "Development Status :: 7 - Inactive",
}

_DEPRECATED_KEYWORDS = {"deprecated", "unmaintained", "abandoned", "obsolete"}


@dataclass
class DeprecationEntry:
    name: str
    version: str
    reason: str  # e.g. "classifier" | "keyword" | "yanked"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class DeprecationReport:
    entries: List[DeprecationEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def deprecated_count(self) -> int:
        return len(self.entries)

    def find(self, name: str) -> Optional[DeprecationEntry]:
        key = _normalize(name)
        return next(
            (e for e in self.entries if _normalize(e.name) == key), None
        )


def _fetch_pypi_info(name: str, session: requests.Session) -> Optional[dict]:
    try:
        url = f"https://pypi.org/pypi/{name}/json"
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def check_deprecation(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
) -> Optional[DeprecationEntry]:
    sess = session or requests.Session()
    data = _fetch_pypi_info(dep.name, sess)
    if data is None:
        return None

    info = data.get("info", {})

    # Check classifiers
    for classifier in info.get("classifiers", []):
        if classifier in _DEPRECATED_CLASSIFIERS:
            return DeprecationEntry(
                name=dep.name,
                version=dep.current_version or "",
                reason="classifier",
                detail=classifier,
            )

    # Check keywords
    keywords_raw = info.get("keywords") or ""
    keywords = {k.strip().lower() for k in keywords_raw.replace(",", " ").split()}
    matched = keywords & _DEPRECATED_KEYWORDS
    if matched:
        return DeprecationEntry(
            name=dep.name,
            version=dep.current_version or "",
            reason="keyword",
            detail=next(iter(matched)),
        )

    # Check yanked latest release
    releases = data.get("releases", {})
    latest = info.get("version", "")
    if latest and releases.get(latest):
        files = releases[latest]
        if files and all(f.get("yanked") for f in files):
            return DeprecationEntry(
                name=dep.name,
                version=dep.current_version or "",
                reason="yanked",
                detail=f"version {latest} is yanked",
            )

    return None


def build_deprecation_report(
    deps: List[ResolvedDep],
    session: Optional[requests.Session] = None,
) -> DeprecationReport:
    sess = session or requests.Session()
    entries: List[DeprecationEntry] = []
    for dep in deps:
        entry = check_deprecation(dep, sess)
        if entry is not None:
            entries.append(entry)
    return DeprecationReport(entries=entries)
