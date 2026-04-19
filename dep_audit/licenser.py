"""Fetch and report license information for resolved dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport


@dataclass
class LicensedDep:
    dep: ResolvedDep
    license: Optional[str] = None

    @property
    def unknown(self) -> bool:
        return not self.license or self.license.lower() in ("unknown", "")


@dataclass
class LicenseReport:
    entries: List[LicensedDep] = field(default_factory=list)

    def unknown_deps(self) -> List[LicensedDep]:
        return [e for e in self.entries if e.unknown]

    def by_license(self) -> Dict[str, List[LicensedDep]]:
        result: Dict[str, List[LicensedDep]] = {}
        for entry in self.entries:
            key = entry.license or "Unknown"
            result.setdefault(key, []).append(entry)
        return result


def fetch_license(package: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """Return the license string for *package* from PyPI, or None on failure."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        s = session or requests.Session()
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data.get("info", {}).get("license") or None
    except Exception:
        return None


def build_license_report(
    report: AuditReport,
    session: Optional[requests.Session] = None,
) -> LicenseReport:
    """Collect license info for every unique dep across all files in *report*."""
    seen: Dict[str, Optional[str]] = {}
    entries: List[LicensedDep] = []

    for file_audit in report.files:
        for dep in file_audit.deps:
            name = dep.name.lower()
            if name not in seen:
                seen[name] = fetch_license(dep.name, session=session)
            entries.append(LicensedDep(dep=dep, license=seen[name]))

    return LicenseReport(entries=entries)
