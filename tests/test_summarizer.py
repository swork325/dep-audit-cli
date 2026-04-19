"""Tests for dep_audit.summarizer."""
import pytest
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.summarizer import (
    build_summary_lines,
    render_summary_text,
    render_summary_json,
)


def _dep(name, current, latest, vulns=None):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulnerabilities=vulns or [],
    )


@pytest.fixture
def report():
    vuln = Vulnerability(id="CVE-1", description="bad", severity="high", fix_version="2.0")
    fa1 = FileAudit(
        path="req.txt",
        deps=[_dep("requests", "2.0", "2.1"), _dep("flask", "1.0", "1.0", [vuln])],
    )
    fa2 = FileAudit(
        path="other.txt",
        deps=[_dep("click", "7.0", "7.0")],
    )
    return AuditReport(files=[fa1, fa2])


def test_build_summary_lines_count(report):
    lines = build_summary_lines(report)
    assert len(lines) == 6


def test_build_summary_lines_labels(report):
    lines = build_summary_lines(report)
    labels = [l.label for l in lines]
    assert "Total files scanned" in labels
    assert "Outdated" in labels
    assert "Vulnerable" in labels


def test_render_summary_text_contains_header(report):
    text = render_summary_text(report)
    assert "Audit Summary" in text


def test_render_summary_text_shows_counts(report):
    text = render_summary_text(report)
    assert "3" in text  # total deps
    assert "2" in text  # total files


def test_render_summary_json_keys(report):
    data = render_summary_json(report)
    assert set(data.keys()) == {
        "total_files", "total_deps", "outdated_deps",
        "vulnerable_deps", "files_with_issues", "issue_rate",
    }


def test_render_summary_json_values(report):
    data = render_summary_json(report)
    assert data["total_files"] == 2
    assert data["total_deps"] == 3
    assert data["outdated_deps"] == 1
    assert data["vulnerable_deps"] == 1


def test_render_summary_json_issue_rate_type(report):
    data = render_summary_json(report)
    assert isinstance(data["issue_rate"], float)


def test_empty_report_no_division_error():
    empty = AuditReport(files=[])
    data = render_summary_json(empty)
    assert data["issue_rate"] == 0.0
    text = render_summary_text(empty)
    assert "0.0%" in text
