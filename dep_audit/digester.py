"""digester.py – produce a concise fingerprint/digest for an AuditReport.

The digest is a stable SHA-256 hex string derived from the sorted set of
(file, package, installed_version, latest_version, vuln_ids) tuples.  Two
reports with identical dependency states produce the same digest, making it
easy to detect whether anything has changed between runs.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import List

from dep_audit.auditor import AuditReport


@dataclass(frozen=True)
class ReportDigest:
    """Holds the hex digest and the number of entries that were hashed."""

    hex: str
    entry_count: int

    def short(self, length: int = 12) -> str:
        """Return the first *length* characters of the digest."""
        return self.hex[:length]

    def matches(self, other: "ReportDigest") -> bool:
        """Return True when both digests are identical."""
        return self.hex == other.hex


def _collect_entries(report: AuditReport) -> List[tuple]:
    """Return a sorted list of tuples representing every dependency."""
    entries: List[tuple] = []
    for file_audit in report.files:
        for dep in file_audit.deps:
            vuln_ids = tuple(
                sorted(v.vuln_id for v in (dep.vulns or []))
            )
            entries.append(
                (
                    str(file_audit.path),
                    dep.name,
                    dep.installed_version or "",
                    dep.latest_version or "",
                    vuln_ids,
                )
            )
    return sorted(entries)


def compute_digest(report: AuditReport) -> ReportDigest:
    """Compute a SHA-256 digest for *report*."""
    entries = _collect_entries(report)
    payload = json.dumps(entries, separators=(",", ":"), sort_keys=True)
    hex_digest = hashlib.sha256(payload.encode()).hexdigest()
    return ReportDigest(hex=hex_digest, entry_count=len(entries))


def digests_match(a: AuditReport, b: AuditReport) -> bool:
    """Return True when two reports produce the same digest."""
    return compute_digest(a).matches(compute_digest(b))
