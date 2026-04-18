"""Tests for dep_audit.filter."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.filter import FilterConfig, filter_report
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability


def _dep(name="pkg", current="1.0", latest="1.0", vulns=None):
    d = MagicMock(spec=ResolvedDep)
    d.name = name
    d.current_version = current
    d.latest_version = latest
    d.is_outdated = current != latest
    d.vulns = vulns or []
    return d


def _vuln(severity="high"):
    v = MagicMock(spec=Vulnerability)
    v.severity = severity
    return v


@pytest.fixture()
def report():
    fa1 = FileAudit(
        path=Path("requirements.txt"),
        deps=[_dep("django", "3.2", "4.2"), _dep("requests", "2.28", "2.28")],
    )
    fa2 = FileAudit(
        path=Path("requirements-dev.txt"),
        deps=[_dep("pytest", "7.0", "7.0", vulns=[_vuln("low")])],
    )
    return AuditReport(files=[fa1, fa2])


def test_only_outdated(report):
    result = filter_report(report, FilterConfig(only_outdated=True))
    names = [d.name for fa in result.files for d in fa.deps]
    assert names == ["django"]


def test_only_vulnerable(report):
    result = filter_report(report, FilterConfig(only_vulnerable=True))
    names = [d.name for fa in result.files for d in fa.deps]
    assert names == ["pytest"]


def test_package_glob(report):
    result = filter_report(report, FilterConfig(package_glob="dj*"))
    names = [d.name for fa in result.files for d in fa.deps]
    assert names == ["django"]


def test_path_glob_excludes_file(report):
    result = filter_report(report, FilterConfig(path_glob="requirements.txt"))
    paths = [str(fa.path) for fa in result.files]
    assert "requirements-dev.txt" not in paths


def test_min_severity_filters_low(report):
    result = filter_report(report, FilterConfig(min_severity="medium"))
    names = [d.name for fa in result.files for d in fa.deps]
    assert "pytest" not in names


def test_no_filter_returns_all(report):
    result = filter_report(report, FilterConfig())
    total = sum(len(fa.deps) for fa in result.files)
    assert total == 3


def test_empty_report():
    result = filter_report(AuditReport(files=[]), FilterConfig(only_outdated=True))
    assert result.files == []
