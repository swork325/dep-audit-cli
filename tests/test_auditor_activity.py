"""Tests for dep_audit.auditor_activity."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor_activity import (
    ActivityEntry,
    ActivityReport,
    _assess,
    _fetch_last_release,
    build_activity_report,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport


def _dep(name="requests", current="2.28.0", latest="2.31.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


def _mock_session(last_release_iso: str | None):
    session = MagicMock()
    if last_release_iso is None:
        session.get.return_value.raise_for_status.side_effect = Exception("err")
    else:
        session.get.return_value.raise_for_status.return_value = None
        session.get.return_value.json.return_value = {
            "releases": {
                "2.28.0": [{"upload_time_iso_8601": last_release_iso}]
            }
        }
    return session


def test_fetch_last_release_returns_datetime():
    iso = "2022-06-01T12:00:00Z"
    session = _mock_session(iso)
    result = _fetch_last_release("requests", session)
    assert isinstance(result, datetime)
    assert result.year == 2022


def test_fetch_last_release_returns_none_on_error():
    session = _mock_session(None)
    result = _fetch_last_release("requests", session)
    assert result is None


def test_fetch_last_release_hits_correct_url():
    session = _mock_session("2023-01-01T00:00:00Z")
    _fetch_last_release("Flask", session)
    url = session.get.call_args[0][0]
    assert "Flask" in url


def test_assess_inactive_when_over_threshold():
    dep = _dep()
    old = datetime.now(timezone.utc) - timedelta(days=400)
    entry = _assess(dep, old, threshold_days=365)
    assert entry.is_inactive is True
    assert entry.days_since_release >= 400


def test_assess_active_when_under_threshold():
    dep = _dep()
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    entry = _assess(dep, recent, threshold_days=365)
    assert entry.is_inactive is False


def test_assess_none_release_not_inactive():
    dep = _dep()
    entry = _assess(dep, None, threshold_days=365)
    assert entry.is_inactive is False
    assert entry.days_since_release is None


def test_activity_entry_to_dict_keys():
    now = datetime.now(timezone.utc)
    e = ActivityEntry(name="x", version="1.0", last_release=now, days_since_release=5, is_inactive=False)
    d = e.to_dict()
    assert set(d.keys()) == {"name", "version", "last_release", "days_since_release", "is_inactive"}


def test_activity_report_inactive_count():
    e1 = ActivityEntry("a", "1", None, None, False)
    e2 = ActivityEntry("b", "2", None, 400, True)
    r = ActivityReport(entries=[e1, e2])
    assert r.inactive_count() == 1
    assert r.total() == 2


def test_activity_report_inactive_only_filters():
    e1 = ActivityEntry("a", "1", None, None, False)
    e2 = ActivityEntry("b", "2", None, 400, True)
    r = ActivityReport(entries=[e1, e2])
    assert r.inactive_only() == [e2]


def test_build_activity_report_deduplicates():
    dep = _dep("requests")
    fa = FileAudit(path="req.txt", deps=[dep, dep])
    report = AuditReport(files=[fa])
    iso = "2020-01-01T00:00:00Z"
    session = _mock_session(iso)
    ar = build_activity_report(report, session=session)
    # two entries (one per dep occurrence) but only one HTTP call
    assert ar.total() == 2
    assert session.get.call_count == 1
