"""Provenance checking: verify that installed packages match expected source URLs."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport


@dataclass
class ProvenanceEntry:
    name: str
    version: Optional[str]
    expected_source: Optional[str]  # e.g. "pypi" or a URL prefix
    actual_url: Optional[str]
    verified: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "expected_source": self.expected_source,
            "actual_url": self.actual_url,
            "verified": self.verified,
        }


@dataclass
class ProvenanceReport:
    entries: list[ProvenanceEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def unverified_count(self) -> int:
        return sum(1 for e in self.entries if not e.verified)

    def unverified(self) -> list[ProvenanceEntry]:
        return [e for e in self.entries if not e.verified]

    def find(self, name: str) -> Optional[ProvenanceEntry]:
        key = name.lower().replace("-", "_")
        for e in self.entries:
            if e.name.lower().replace("-", "_") == key:
                return e
        return None


def _fetch_pypi_url(name: str, version: Optional[str], session: requests.Session) -> Optional[str]:
    """Return the first release download URL from PyPI for the given package/version."""
    try:
        ver = version or "latest"
        url = f"https://pypi.org/pypi/{name}/{ver}/json" if version else f"https://pypi.org/pypi/{name}/json"
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        urls = data.get("urls") or []
        if urls:
            return urls[0].get("url")
        releases = data.get("releases", {})
        rel_ver = data.get("info", {}).get("version", "")
        files = releases.get(rel_ver, [])
        return files[0].get("url") if files else None
    except Exception:
        return None


def check_provenance(
    report: AuditReport,
    expected_source: str = "pypi.org",
    session: Optional[requests.Session] = None,
) -> ProvenanceReport:
    """Build a ProvenanceReport for all deps in the audit report."""
    sess = session or requests.Session()
    seen: dict[str, ProvenanceEntry] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower().replace("-", "_")
            if key in seen:
                continue
            actual_url = _fetch_pypi_url(dep.name, dep.version, sess)
            verified = actual_url is not None and expected_source in actual_url
            seen[key] = ProvenanceEntry(
                name=dep.name,
                version=dep.version,
                expected_source=expected_source,
                actual_url=actual_url,
                verified=verified,
            )
    return ProvenanceReport(entries=list(seen.values()))
