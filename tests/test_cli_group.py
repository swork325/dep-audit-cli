"""Tests for dep_audit.cli_group."""
import argparse
import pytest
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.vulnerability import Vulnerability
from dep_audit.cli_group import add_group_args, render_grouped


def _dep(name, severity=None):
    vulns = [Vulnerability(id="CVE-1", description="d", severity=severity, fix_version=None)] if severity else []
    return ResolvedDep(name=name, current_version="1.0", latest_version="1.0", vulns=vulns)


def _parse(args):
    p = argparse.ArgumentParser()
    add_group_args(p)
    return p.parse_args(args)


@pytest.fixture
def report():
    fa1 = FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask", severity="HIGH")])
    fa2 = FileAudit(path="dev.txt", deps=[_dep("requests")])
    return AuditReport(files=[fa1, fa2])


def test_default_group_by_is_none():
    ns = _parse([])
    assert ns.group_by is None


def test_group_by_package_flag():
    ns = _parse(["--group-by", "package"])
    assert ns.group_by == "package"


def test_render_grouped_by_package_contains_name(report):
    out = render_grouped(report, "package")
    assert "requests" in out


def test_render_grouped_by_package_shows_both_files(report):
    out = render_grouped(report, "package")
    line = [l for l in out.splitlines() if "requests" in l][0]
    assert "req.txt" in line and "dev.txt" in line


def test_render_grouped_by_severity_shows_high(report):
    out = render_grouped(report, "severity")
    assert "HIGH" in out


def test_render_grouped_by_file_shows_paths(report):
    out = render_grouped(report, "file")
    assert "req.txt" in out
    assert "dev.txt" in out


def test_render_grouped_by_file_shows_dep_names(report):
    out = render_grouped(report, "file")
    assert "flask" in out
