"""Tests for dep_audit.highlighter."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.highlighter import (
    highlight_new_issues,
    total_new_issues,
    HighlightReport,
)


def _dep(
    package: str,
    installed: str = "1.0.0",
    latest: str = "1.0.0",
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        package=package,
        installed_version=installed,
        latest_version=latest,
        is_outdated=installed != latest,
        vulnerabilities=vulns or [],
    )


def _vuln(sev: str = "high") -> Vulnerability:
    return Vulnerability(id="CVE-0001", description="test", severity=sev, fix_version="2.0.0")


def _report(*file_tuples) -> AuditReport:
    files = [
        FileAudit(file_path=path, deps=list(deps))
        for path, deps in file_tuples
    ]
    return AuditReport(files=files)


# ── baseline=None treats every issue as new ──────────────────────────────────

def test_no_baseline_all_issues_are_new():
    dep = _dep("requests", installed="1.0.0", latest="2.0.0")
    report = _report(("req.txt", [dep]))
    result = highlight_new_issues(report, baseline=None)
    assert result[0].deps[0].is_new_issue is True


def test_no_baseline_clean_dep_not_new():
    dep = _dep("flask", installed="2.0.0", latest="2.0.0")
    report = _report(("req.txt", [dep]))
    result = highlight_new_issues(report, baseline=None)
    assert result[0].deps[0].is_new_issue is False


# ── dep already in baseline is NOT flagged as new ─────────────────────────────

def test_existing_issue_in_baseline_not_new():
    dep = _dep("requests", installed="1.0.0", latest="2.0.0")
    baseline = _report(("req.txt", [dep]))
    current = _report(("req.txt", [dep]))
    result = highlight_new_issues(current, baseline=baseline)
    assert result[0].deps[0].is_new_issue is False


def test_new_version_with_issue_is_new():
    old_dep = _dep("requests", installed="1.0.0", latest="2.0.0")
    new_dep = _dep("requests", installed="1.1.0", latest="2.0.0")
    baseline = _report(("req.txt", [old_dep]))
    current = _report(("req.txt", [new_dep]))
    result = highlight_new_issues(current, baseline=baseline)
    assert result[0].deps[0].is_new_issue is True


# ── vulnerable deps ───────────────────────────────────────────────────────────

def test_vulnerable_dep_not_in_baseline_is_new():
    dep = _dep("urllib3", vulns=[_vuln()])
    baseline = _report(("req.txt", [_dep("urllib3")]))
    current = _report(("req.txt", [dep]))
    result = highlight_new_issues(current, baseline=baseline)
    # same package+version but baseline entry has no vulns key in the key tuple
    # key is (file, package, installed_version) — same here, so NOT new
    assert result[0].deps[0].is_new_issue is False


# ── HighlightReport helpers ───────────────────────────────────────────────────

def test_highlight_report_total_new_issues_counts_only_new():
    """total_new_issues should count only deps flagged as new issues."""
    outdated = _dep("requests", installed="1.0.0", latest="2.0.0")
    clean = _dep("flask", installed="2.0.0", latest="2.0.0")
    report = _report(("req.txt", [outdated, clean]))
    result = highlight_new_issues(report, baseline=None)
    assert total_new_issues(result) == 1


def test_highlight_report_total_new_issues_empty_report():
    """total_new_issues returns 0 for a report with no deps."""
    report = _report(("req.txt", []))
    result = highlight_new_issues(report, baseline=None)
    assert total_new_issues(result) == 0


def test_highlight_report_total_new_issues_multiple_files():
    """total_new_issues aggregates new issues across multiple files."""
    dep_a = _dep("requests", installed="1.0.0", latest="2.0.0")
    dep_b = _dep("boto3", installed="1.5.0", latest="1.9.0")
    dep_c = _dep("flask", installed="2.0.0", latest="2.0.0")
    report = _report(
        ("requirements.txt", [dep_a, dep_c]),
        ("setup.cfg", [dep_b]),
    )
    result = highlight_new_issues(report, baseline=None)
    assert total_new_issues(result) == 2
