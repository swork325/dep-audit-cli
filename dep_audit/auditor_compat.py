"""Python version compatibility checker for dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class CompatEntry:
    package: str
    current_version: Optional[str]
    requires_python: Optional[str]
    compatible: bool
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "current_version": self.current_version,
            "requires_python": self.requires_python,
            "compatible": self.compatible,
            "reason": self.reason,
        }


@dataclass
class CompatReport:
    entries: List[CompatEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def incompatible_count(self) -> int:
        return sum(1 for e in self.entries if not e.compatible)

    @property
    def incompatible(self) -> List[CompatEntry]:
        return [e for e in self.entries if not e.compatible]

    def by_package(self) -> Dict[str, CompatEntry]:
        return {e.package: e for e in self.entries}


def _is_compatible(requires_python: Optional[str], runtime: str) -> tuple[bool, str]:
    """Check whether *runtime* satisfies *requires_python* specifier."""
    if not requires_python:
        return True, ""
    try:
        from packaging.specifiers import SpecifierSet
        spec = SpecifierSet(requires_python)
        ok = runtime in spec
        reason = "" if ok else f"{runtime} does not satisfy {requires_python}"
        return ok, reason
    except Exception as exc:  # pragma: no cover
        return True, f"could not parse specifier: {exc}"


def build_compat_report(
    report: AuditReport,
    runtime: str,
    extras_map: Optional[Dict[str, Optional[str]]] = None,
) -> CompatReport:
    """Build a CompatReport for *runtime* (e.g. '3.9') from *report*.

    *extras_map* maps normalised package names to their ``requires_python``
    string as returned by :func:`dep_audit.auditor_extras.fetch_extras`.
    """
    extras_map = extras_map or {}
    entries: List[CompatEntry] = []
    seen: set = set()

    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower().replace("-", "_")
            if key in seen:
                continue
            seen.add(key)
            req_py = extras_map.get(key)
            ok, reason = _is_compatible(req_py, runtime)
            entries.append(
                CompatEntry(
                    package=dep.name,
                    current_version=dep.current_version,
                    requires_python=req_py,
                    compatible=ok,
                    reason=reason,
                )
            )

    return CompatReport(entries=entries)
