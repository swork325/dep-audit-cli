"""Tests for dep_audit.licenser."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.licenser import (
    LicensedDep,
    LicenseReport,
    fetch_license,
    build_license_report,
)


def _dep(name: str = "requests", current: str = "2.28.0", latest: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


def _mock_session(license_str: str = "MIT") -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"info": {"license": license_str}}
    resp.raise_for_status = MagicMock()
    session = MagicMock()
    session.get.return_value = resp
    return session


def test_fetch_license_returns_license():
    session = _mock_session("Apache-2.0")
    result = fetch_license("requests", session=session)
    assert result == "Apache-2.0"


def test_fetch_license_returns_none_on_error():
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    result = fetch_license("requests", session=session)
    assert result is None


def test_fetch_license_returns_none_when_empty_string():
    session = _mock_session("")
    result = fetch_license("flask", session=session)
    assert result is None


def test_fetch_license_hits_correct_url():
    session = _mock_session("MIT")
    fetch_license("numpy", session=session)
    call_url = session.get.call_args[0][0]
    assert "numpy" in call_url
    assert "pypi.org" in call_url


def test_licensed_dep_unknown_when_none():
    dep = _dep()
    ld = LicensedDep(dep=dep, license=None)
    assert ld.unknown is True


def test_licensed_dep_not_unknown_with_license():
    dep = _dep()
    ld = LicensedDep(dep=dep, license="MIT")
    assert ld.unknown is False


def test_license_report_unknown_deps():
    dep1 = LicensedDep(dep=_dep("requests"), license="MIT")
    dep2 = LicensedDep(dep=_dep("flask"), license=None)
    lr = LicenseReport(entries=[dep1, dep2])
    assert len(lr.unknown_deps()) == 1
    assert lr.unknown_deps()[0].dep.name == "flask"


def test_license_report_by_license_groups_correctly():
    dep1 = LicensedDep(dep=_dep("requests"), license="MIT")
    dep2 = LicensedDep(dep=_dep("flask"), license="MIT")
    dep3 = LicensedDep(dep=_dep("numpy"), license="BSD")
    lr = LicenseReport(entries=[dep1, dep2, dep3])
    grouped = lr.by_license()
    assert len(grouped["MIT"]) == 2
    assert len(grouped["BSD"]) == 1


def test_build_license_report_deduplicates_fetches():
    session = _mock_session("MIT")
    dep = _dep("requests")
    file_audit = FileAudit(path="requirements.txt", deps=[dep, dep])
    report = AuditReport(files=[file_audit])
    build_license_report(report, session=session)
    # same package fetched only once despite appearing twice
    assert session.get.call_count == 1


def test_build_license_report_entries_count():
    session = _mock_session("MIT")
    dep1 = _dep("requests")
    dep2 = _dep("flask")
    file_audit = FileAudit(path="requirements.txt", deps=[dep1, dep2])
    report = AuditReport(files=[file_audit])
    lr = build_license_report(report, session=session)
    assert len(lr.entries) == 2
