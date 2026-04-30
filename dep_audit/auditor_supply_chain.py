"""Supply-chain risk analysis: detect typosquatting candidates and
unrecognised namespaces across resolved dependencies."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport

# Well-known package namespaces / popular packages used for similarity checks
_KNOWN_POPULAR: frozenset[str] = frozenset({
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "boto3", "click", "pydantic", "fastapi", "sqlalchemy",
    "pytest", "setuptools", "pip", "wheel", "cryptography",
})


def _edit_distance(a: str, b: str) -> int:
    """Simple Levenshtein distance."""
    if a == b:
        return 0
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            prev, dp[j] = dp[j], prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
    return dp[n]


def _is_typosquat_candidate(name: str, threshold: int = 2) -> Optional[str]:
    """Return the popular package name if *name* looks like a typosquat."""
    normalised = re.sub(r"[-_.]+", "-", name.lower())
    for known in _KNOWN_POPULAR:
        if normalised == known:
            return None
        if _edit_distance(normalised, known) <= threshold:
            return known
    return None


@dataclass
class SupplyChainEntry:
    package: str
    version: str
    typosquat_of: Optional[str] = None
    suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "typosquat_of": self.typosquat_of,
            "suspicious": self.suspicious,
        }


@dataclass
class SupplyChainReport:
    entries: List[SupplyChainEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for e in self.entries if e.suspicious)

    def suspicious_entries(self) -> List[SupplyChainEntry]:
        return [e for e in self.entries if e.suspicious]


def build_supply_chain_report(
    report: AuditReport,
    extra_known: Optional[Sequence[str]] = None,
    threshold: int = 2,
) -> SupplyChainReport:
    """Analyse all resolved deps in *report* for supply-chain risks."""
    known = _KNOWN_POPULAR | frozenset(n.lower() for n in (extra_known or []))
    entries: List[SupplyChainEntry] = []
    seen: set[str] = set()
    for fa in report.files:
        for dep in fa.deps:
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            typosquat_of = _is_typosquat_candidate.__wrapped__(dep.name, known, threshold) \
                if hasattr(_is_typosquat_candidate, "__wrapped__") \
                else _check_against(dep.name, known, threshold)
            entries.append(SupplyChainEntry(
                package=dep.name,
                version=dep.current_version or "",
                typosquat_of=typosquat_of,
                suspicious=typosquat_of is not None,
            ))
    return SupplyChainReport(entries=entries)


def _check_against(name: str, known: frozenset[str], threshold: int) -> Optional[str]:
    normalised = re.sub(r"[-_.]+", "-", name.lower())
    for k in known:
        if normalised == k:
            return None
        if _edit_distance(normalised, k) <= threshold:
            return k
    return None
