"""Dependency profile: aggregate per-package metadata across an AuditReport."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability


@dataclass
class DepProfile:
    name: str
    current_versions: List[str] = field(default_factory=list)
    latest_version: Optional[str] = None
    is_outdated: bool = False
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    files: List[str] = field(default_factory=list)

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def highest_severity(self) -> Optional[str]:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not self.vulnerabilities:
            return None
        return max(
            (v.severity for v in self.vulnerabilities),
            key=lambda s: order.get(s.lower(), 0),
        )


def build_profiles(report: AuditReport) -> Dict[str, DepProfile]:
    """Return a mapping of package name -> DepProfile aggregated across all files."""
    profiles: Dict[str, DepProfile] = {}

    for file_audit in report.files:
        for dep in file_audit.deps:
            name_key = dep.name.lower()
            if name_key not in profiles:
                profiles[name_key] = DepProfile(name=dep.name)
            prof = profiles[name_key]

            if dep.current_version and dep.current_version not in prof.current_versions:
                prof.current_versions.append(dep.current_version)

            if dep.latest_version:
                prof.latest_version = dep.latest_version

            if dep.is_outdated:
                prof.is_outdated = True

            for vuln in dep.vulnerabilities:
                if vuln.id not in {v.id for v in prof.vulnerabilities}:
                    prof.vulnerabilities.append(vuln)

            if file_audit.path not in prof.files:
                prof.files.append(file_audit.path)

    return profiles
