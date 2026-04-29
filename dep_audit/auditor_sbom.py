"""SBOM (Software Bill of Materials) generation for audited dependencies."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


@dataclass
class SBOMComponent:
    name: str
    version: Optional[str]
    source_file: str
    is_outdated: bool
    is_vulnerable: bool

    def to_dict(self) -> dict:
        return {
            "type": "library",
            "name": self.name,
            "version": self.version or "unknown",
            "source_file": self.source_file,
            "properties": [
                {"name": "dep-audit:outdated", "value": str(self.is_outdated).lower()},
                {"name": "dep-audit:vulnerable", "value": str(self.is_vulnerable).lower()},
            ],
        }


@dataclass
class SBOMDocument:
    bom_ref: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    components: List[SBOMComponent] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.components)

    def to_dict(self) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{self.bom_ref}",
            "version": 1,
            "metadata": {
                "timestamp": self.timestamp,
                "tools": [{"name": "dep-audit-cli", "version": "1.0.0"}],
            },
            "components": [c.to_dict() for c in self.components],
        }


def _dep_is_vulnerable(dep: ResolvedDep) -> bool:
    return bool(dep.vulns)


def build_sbom(report: AuditReport) -> SBOMDocument:
    """Build a CycloneDX-style SBOM document from an AuditReport."""
    doc = SBOMDocument()
    seen: set[tuple[str, Optional[str]]] = set()
    for fa in report.files:
        for dep in fa.deps:
            key = (dep.name.lower(), dep.version)
            if key in seen:
                continue
            seen.add(key)
            doc.components.append(
                SBOMComponent(
                    name=dep.name,
                    version=dep.version,
                    source_file=fa.path,
                    is_outdated=dep.latest is not None and dep.version != dep.latest,
                    is_vulnerable=_dep_is_vulnerable(dep),
                )
            )
    return doc


def save_sbom(doc: SBOMDocument, path: str) -> None:
    """Serialise the SBOM document to a JSON file."""
    Path(path).write_text(json.dumps(doc.to_dict(), indent=2), encoding="utf-8")
