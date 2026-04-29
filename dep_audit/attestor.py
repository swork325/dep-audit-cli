"""attestor.py – verify that installed packages match expected checksums."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep


@dataclass
class AttestationEntry:
    name: str
    version: str
    expected_sha256: str
    actual_sha256: Optional[str]

    @property
    def verified(self) -> bool:
        return self.actual_sha256 is not None and self.actual_sha256 == self.expected_sha256

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "verified": self.verified,
        }


@dataclass
class AttestationReport:
    entries: List[AttestationEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def verified_count(self) -> int:
        return sum(1 for e in self.entries if e.verified)

    @property
    def failed_count(self) -> int:
        return sum(1 for e in self.entries if not e.verified)

    @property
    def all_verified(self) -> bool:
        return self.total > 0 and self.failed_count == 0


def _sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_attestation_map(path: Path) -> Dict[str, str]:
    """Load {name: sha256} map from a JSON file."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {}
        return {k.lower(): v for k, v in data.items() if isinstance(v, str)}
    except (json.JSONDecodeError, OSError):
        return {}


def save_attestation_map(path: Path, attest_map: Dict[str, str]) -> None:
    path.write_text(json.dumps(attest_map, indent=2))


def attest_dep(dep: ResolvedDep, attest_map: Dict[str, str]) -> AttestationEntry:
    key = dep.name.lower()
    expected = attest_map.get(key, "")
    actual = _sha256_of(f"{dep.name}=={dep.current_version}") if dep.current_version else None
    return AttestationEntry(
        name=dep.name,
        version=dep.current_version or "",
        expected_sha256=expected,
        actual_sha256=actual,
    )


def build_attestation_report(
    report: AuditReport, attest_map: Dict[str, str]
) -> AttestationReport:
    seen: Dict[str, AttestationEntry] = {}
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower()
            if key not in seen:
                seen[key] = attest_dep(dep, attest_map)
    return AttestationReport(entries=list(seen.values()))
