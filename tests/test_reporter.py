"""Tests for dep_audit.reporter."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.reporter import compute_stats, build_top_issues, summarize


def _dep(
    name="pkg",
    installed="1.0.0",
    latest="1.0.0",
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        installed=installed,
        latest=latest,
        vulns=vulns or [],
    )


def _vuln(vid="CVE-001", desc="A bug") -> Vulnerability:
    return Vulnerability(vuln_id=vid, description=desc, severity="HIGH", fix_version=None)


@pytest.fixture
def report() -> AuditReport:
    fa1 = FileAudit(
        path="requirements.txt",
        deps=[
            _dep("requests", "2.0.0", "2.28.0"),
            _dep("flask", "2.2.0", "2.2.0", vulns=[_vuln("CVE-001", "XSS issue")]),
        ],
    )
    fa2 = FileAudit(
        path="requirements-dev.txt",
        deps=[
            _dep("pytest", "7.0.0", "7.0.0"),
        ],
    )
    return AuditReport(file_audits=[fa1, fa2])


def test_compute_stats_total_files(report):
    stats = compute_stats(report)
    assert stats.total_files == 2


def test_compute_stats_total_deps(report):
    stats = compute_stats(report)
    assert stats.total_deps == 3


def test_compute_stats_outdated(report):
    stats = compute_stats(report)
    assert stats.outdated_count == 1


def test_compute_stats_vulnerable(report):
    stats = compute_stats(report)
    assert stats.vulnerable_count == 1
    assert stats.unique_vulnerabilities == 1


def test_compute_stats_files_with_issues(report):
    stats = compute_stats(report)
    assert stats.files_with_issues == 2


def test_clean_files(report):
    stats = compute_stats(report)
    assert stats.clean_files == 0


def test_issue_rate(report):
    stats = compute_stats(report)
    assert stats.issue_rate == 100.0


def test_issue_rate_no_files():
    empty = AuditReport(file_audits=[])
    stats = compute_stats(empty)
    assert stats.issue_rate == 0.0


def test_build_top_issues_returns_descriptions(report):
    issues = build_top_issues(report)
    assert any("XSS issue" in i for i in issues)


def test_build_top_issues_respects_limit(report):
    issues = build_top_issues(report, limit=1)
    assert len(issues) <= 1


def test_summarize_returns_project_summary(report):
    summary = summarize(report)
    assert summary.stats.total_files == 2
    assert isinstance(summary.top_issues, list)
    assert summary.report is report
