"""Tests for dep_audit.differ."""
import pytest
from unittest.mock import MagicMock

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.differ import diff_reports, ReportDiff, DepDiff


def _dep(name, current="1.0", latest="2.0", outdated=False, vulns=None):
    d = MagicMock(spec=ResolvedDep)
    d.name = name
    d.current = current
    d.latest = latest
    d.is_outdated = outdated
    d.vulns = vulns or []
    return d


def _vuln(vuln_id, summary="bad"):
    v = MagicMock(spec=Vulnerability)
    v.vuln_id = vuln_id
    v.summary = summary
    return v


def _report(*file_audits):
    r = MagicMock(spec=AuditReport)
    r.files = list(file_audits)
    return r


def _file(path, deps):
    fa = MagicMock(spec=FileAudit)
    fa.path = path
    fa.deps = deps
    return fa


def test_no_changes_returns_empty_diff():
    dep = _dep("requests", outdated=True)
    before = _report(_file("req.txt", [dep]))
    after = _report(_file("req.txt", [dep]))
    result = diff_reports(before, after)
    assert not result.has_new_issues
    assert result.total_changes == 0


def test_new_outdated_dep_detected():
    before = _report(_file("req.txt", [_dep("flask", outdated=False)]))
    after = _report(_file("req.txt", [_dep("flask", outdated=True)]))
    result = diff_reports(before, after)
    assert result.has_new_issues
    assert any(d.package == "flask" and d.kind == "outdated" for d in result.new_issues)


def test_resolved_outdated_dep_detected():
    before = _report(_file("req.txt", [_dep("flask", outdated=True)]))
    after = _report(_file("req.txt", [_dep("flask", outdated=False)]))
    result = diff_reports(before, after)
    assert not result.has_new_issues
    assert any(d.package == "flask" for d in result.resolved_issues)


def test_new_vuln_detected():
    vuln = _vuln("CVE-2024-001")
    before = _report(_file("req.txt", [_dep("django")]))
    after = _report(_file("req.txt", [_dep("django", vulns=[vuln])]))
    result = diff_reports(before, after)
    assert result.has_new_issues
    assert any("CVE-2024-001" in d.kind for d in result.new_issues)


def test_new_file_with_issues_counted():
    before = _report()
    after = _report(_file("new_req.txt", [_dep("boto3", outdated=True)]))
    result = diff_reports(before, after)
    assert result.has_new_issues
    assert result.new_issues[0].file_path == "new_req.txt"


def test_total_changes_sums_both_directions():
    dep_a = _dep("a", outdated=True)
    dep_b = _dep("b", outdated=False)
    dep_b_new = _dep("b", outdated=True)
    before = _report(_file("r.txt", [dep_a, dep_b]))
    after = _report(_file("r.txt", [dep_b_new]))
    result = diff_reports(before, after)
    # dep_a resolved, dep_b newly outdated
    assert result.total_changes == 2
