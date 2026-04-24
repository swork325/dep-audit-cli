"""Tests for dep_audit.reporter_health."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.reporter_health import (
    HealthScore,
    _letter_grade,
    _vuln_penalty,
    compute_health,
)


def _dep(
    name: str = "pkg",
    version: str = "1.0.0",
    latest: str = "1.0.0",
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        version=version,
        latest=latest,
        is_outdated=(version != latest),
        vulns=vulns or [],
    )


def _vuln(severity: str = "high") -> Vulnerability:
    return Vulnerability(id="CVE-0", description="x", severity=severity, fix_version=None)


def _report(*file_audits: FileAudit) -> AuditReport:
    return AuditReport(files=list(file_audits))


def _fa(path: str, *deps: ResolvedDep) -> FileAudit:
    return FileAudit(path=path, deps=list(deps))


# --- _letter_grade ---

@pytest.mark.parametrize("score,expected", [
    (100, "A"), (90, "A"), (89, "B"), (75, "B"),
    (74, "C"), (60, "C"), (59, "D"), (40, "D"),
    (39, "F"), (0, "F"),
])
def test_letter_grade(score, expected):
    assert _letter_grade(score) == expected


# --- _vuln_penalty ---

def test_vuln_penalty_empty():
    assert _vuln_penalty([]) == 0


def test_vuln_penalty_sums_weights():
    vulns = [_vuln("critical"), _vuln("low")]
    assert _vuln_penalty(vulns) == 40 + 5


def test_vuln_penalty_unknown_severity_defaults_to_five():
    assert _vuln_penalty([_vuln("unknown")]) == 5


# --- compute_health ---

def test_compute_health_empty_report_is_perfect():
    hs = compute_health(_report())
    assert hs.score == 100
    assert hs.grade == "A"
    assert hs.total_deps == 0


def test_compute_health_all_clean_is_perfect():
    fa = _fa("req.txt", _dep("a"), _dep("b"))
    hs = compute_health(_report(fa))
    assert hs.score == 100
    assert hs.outdated_count == 0
    assert hs.vuln_count == 0


def test_compute_health_outdated_reduces_score():
    fa = _fa("req.txt", _dep("a", "1.0", "2.0"))
    hs = compute_health(_report(fa))
    assert hs.outdated_count == 1
    assert hs.score < 100


def test_compute_health_vuln_reduces_score():
    fa = _fa("req.txt", _dep("a", vulns=[_vuln("high")]))
    hs = compute_health(_report(fa))
    assert hs.vuln_count == 1
    assert hs.score < 100


def test_compute_health_score_never_negative():
    vulns = [_vuln("critical")] * 20
    fa = _fa("req.txt", _dep("a", "1.0", "2.0", vulns=vulns))
    hs = compute_health(_report(fa))
    assert hs.score >= 0


def test_compute_health_returns_health_score_instance():
    hs = compute_health(_report())
    assert isinstance(hs, HealthScore)
