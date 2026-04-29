"""License compatibility checker — flags deps whose licenses conflict with a
given project license (e.g. GPL in a proprietary project)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport

# Licenses that are incompatible with common project license policies.
# Keys are project license families; values are sets of dep licenses to flag.
_INCOMPATIBLE: Dict[str, set] = {
    "proprietary": {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"},
    "apache-2.0": {"GPL-2.0", "GPL-3.0", "AGPL-3.0"},
    "mit": {"AGPL-3.0"},
}


@dataclass
class LicenseCompatEntry:
    package: str
    version: Optional[str]
    dep_license: Optional[str]
    project_license: str
    compatible: bool

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "dep_license": self.dep_license,
            "project_license": self.project_license,
            "compatible": self.compatible,
        }


@dataclass
class LicenseCompatReport:
    entries: List[LicenseCompatEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def incompatible_count(self) -> int:
        return sum(1 for e in self.entries if not e.compatible)

    def incompatible(self) -> List[LicenseCompatEntry]:
        return [e for e in self.entries if not e.compatible]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "incompatible_count": self.incompatible_count,
            "entries": [e.to_dict() for e in self.entries],
        }


def _is_compatible(dep_license: Optional[str], project_license: str) -> bool:
    if dep_license is None:
        return True  # unknown — don't flag
    blocked = _INCOMPATIBLE.get(project_license.lower(), set())
    return dep_license not in blocked


def check_license_compat(
    report: AuditReport,
    project_license: str,
    license_map: Dict[str, Optional[str]],
) -> LicenseCompatReport:
    """Build a LicenseCompatReport from an AuditReport.

    *license_map* maps normalised package names to their SPDX license
    identifiers (or None when unknown).
    """
    entries: List[LicenseCompatEntry] = []
    seen: set = set()
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            dep_lic = license_map.get(key)
            entries.append(
                LicenseCompatEntry(
                    package=dep.name,
                    version=dep.current_version,
                    dep_license=dep_lic,
                    project_license=project_license,
                    compatible=_is_compatible(dep_lic, project_license),
                )
            )
    return LicenseCompatReport(entries=entries)
