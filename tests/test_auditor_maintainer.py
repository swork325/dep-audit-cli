"""Tests for dep_audit.auditor_maintainer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_maintainer import (
    MaintainerEntry,
    MaintainerReport,
    _fetch_last_release_date,
    build_maintainer_report,
    check_maintainer,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str = "requests", installed: str = "2.28.0", latest: str = "2.31.0") -> ResolvedDep:
    return ResolvedDep(name=name, installed=installed, latest=latest, vulns=VulnResult(package=name, vulnerabilities=[]))


def _mock_session(days_ago: int = 100, raise_error: bool = False) -> MagicMock:
    session = MagicMock()
    if raise_error:
        session.get.side_effect = Exception("network error")
        return session
    ts = (datetime.now(tz=timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    payload = {
        "info": {"version": "2.31.0"},
        "releases": {
            "2.31.0": [{"upload_time_iso_8601": ts}]
        },
    }
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    session.get.return_value = resp
    return session


def test_fetch_last_release_date_returns_datetime():
    session = _mock_session(days_ago=30)
    result = _fetch_last_release_date("requests", session)
    assert isinstance(result, datetime)


def test_fetch_last_release_date_returns_none_on_error():
    session = _mock_session(raise_error=True)
    result = _fetch_last_release_date("requests", session)
    assert result is None


def test_fetch_last_release_date_hits_pypi_url():
    session = _mock_session(days_ago=10)
    _fetch_last_release_date("flask", session)
    call_url = session.get.call_args[0][0]
    assert "flask" in call_url
    assert "pypi.org" in call_url


def test_check_maintainer_is_maintained_when_recent():
    dep = _dep()
    session = _mock_session(days_ago=30)
    entry = check_maintainer(dep, session, stale_days=365)
    assert entry.is_maintained is True
    assert entry.days_since_release is not None
    assert entry.days_since_release <= 365


def test_check_maintainer_unmaintained_when_stale():
    dep = _dep()
    session = _mock_session(days_ago=400)
    entry = check_maintainer(dep, session, stale_days=365)
    assert entry.is_maintained is False


def test_check_maintainer_unmaintained_when_date_unavailable():
    dep = _dep()
    session = _mock_session(raise_error=True)
    entry = check_maintainer(dep, session)
    assert entry.is_maintained is False
    assert entry.days_since_release is None


def test_maintainer_entry_to_dict_keys():
    dep = _dep()
    session = _mock_session(days_ago=50)
    entry = check_maintainer(dep, session)
    d = entry.to_dict()
    assert set(d.keys()) == {"name", "latest_version", "last_release_date", "days_since_release", "is_maintained"}


def test_maintainer_report_total_and_unmaintained():
    entries = [
        MaintainerEntry("requests", "2.31.0", None, None, False),
        MaintainerEntry("flask", "3.0.0", None, 10, True),
        MaintainerEntry("old-lib", "0.1.0", None, 800, False),
    ]
    report = MaintainerReport(entries=entries)
    assert report.total == 3
    assert report.unmaintained_count == 2
    assert {e.name for e in report.unmaintained()} == {"requests", "old-lib"}


def test_build_maintainer_report_deduplicates():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    audit = AuditReport(files=[fa1, fa2])
    session = _mock_session(days_ago=20)
    result = build_maintainer_report(audit, session=session)
    assert result.total == 1


def test_build_maintainer_report_multiple_packages():
    dep1 = _dep("requests")
    dep2 = _dep("flask", installed="2.0.0", latest="3.0.0")
    fa = FileAudit(path="requirements.txt", deps=[dep1, dep2])
    audit = AuditReport(files=[fa])
    session = _mock_session(days_ago=50)
    result = build_maintainer_report(audit, session=session)
    assert result.total == 2
