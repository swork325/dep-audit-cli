"""Tests for dep_audit.grouper."""
import pytest
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.vulnerability import Vulnerability, VulnResult
from dep_audit.grouper import group_by_package, group_by_severity, group_by_file, group_report


def _dep(name, outdated=False, severity=None):
    vulns = []
    if severity:
        vulns = [Vulnerability(id="CVE-1", description="x", severity=severity, fix_version=None)]
    vr = VulnResult(package=name, vulns=vulns)
    return ResolvedDep(
        name=name,
        current_version="1.0.0",
        latest_version="2.0.0" if outdated else "1.0.0",
        vulns=vulns,
    )


@pytest.fixture
def report():
    fa1 = FileAudit(path="req.txt", deps=[_dep("requests", outdated=True), _dep("flask")])
    fa2 = FileAudit(path="dev.txt", deps=[_dep("requests"), _dep("pytest", severity="HIGH")])
    return AuditReport(files=[fa1, fa2])


def test_group_by_package_keys(report):
    result = group_by_package(report)
    assert set(result.keys()) == {"requests", "flask", "pytest"}


def test_group_by_package_requests_in_two_files(report):
    result = group_by_package(report)
    assert len(result["requests"]) == 2


def test_group_by_package_flask_in_one_file(report):
    result = group_by_package(report)
    assert len(result["flask"]) == 1


def test_group_by_severity_high_present(report):
    result = group_by_severity(report)
    assert "HIGH" in result


def test_group_by_severity_high_contains_pytest(report):
    result = group_by_severity(report)
    names = [d.name for d in result["HIGH"]]
    assert "pytest" in names


def test_group_by_file_keys(report):
    result = group_by_file(report)
    assert set(result.keys()) == {"req.txt", "dev.txt"}


def test_group_report_returns_grouped_report(report):
    gr = group_report(report)
    assert gr.by_package
    assert gr.by_file


def test_group_by_severity_no_vulns():
    fa = FileAudit(path="r.txt", deps=[_dep("boto3")])
    r = AuditReport(files=[fa])
    assert group_by_severity(r) == {}
