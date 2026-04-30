"""Tests for dep_audit.auditor_age."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_age import (
    AgeEntry,
    AgeReport,
    _fetch_release_date,
    _age_entry,
    build_age_report,
    _OLD_THRESHOLD_DAYS,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str = "requests", version: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version="2.31.0",
        is_outdated=False,
        vulnerabilities=[],
    )


def _mock_session(upload_time: str) -> MagicMock:
    sess = MagicMock()
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "releases": {
            "2.28.0": [{"upload_time_iso_8601": upload_time}]
        }
    }
    sess.get.return_value = resp
    return sess


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# AgeEntry.to_dict
# ---------------------------------------------------------------------------

def test_age_entry_to_dict_keys():
    entry = AgeEntry(
        name="requests",
        version="2.28.0",
        release_date=None,
        age_days=None,
        is_old=False,
    )
    d = entry.to_dict()
    assert set(d.keys()) == {"name", "version", "release_date", "age_days", "is_old"}


def test_age_entry_to_dict_with_date():
    dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
    entry = AgeEntry(name="flask", version="1.0", release_date=dt, age_days=1200, is_old=True)
    d = entry.to_dict()
    assert d["release_date"] == dt.isoformat()
    assert d["age_days"] == 1200
    assert d["is_old"] is True


# ---------------------------------------------------------------------------
# AgeReport helpers
# ---------------------------------------------------------------------------

def test_age_report_total():
    e1 = AgeEntry("a", "1.0", None, None, False)
    e2 = AgeEntry("b", "2.0", None, None, True)
    r = AgeReport(entries=[e1, e2])
    assert r.total == 2


def test_age_report_old_count():
    e1 = AgeEntry("a", "1.0", None, None, False)
    e2 = AgeEntry("b", "2.0", None, None, True)
    r = AgeReport(entries=[e1, e2])
    assert r.old_count == 1


def test_age_report_find_normalises_hyphens():
    e = AgeEntry("my-pkg", "1.0", None, None, False)
    r = AgeReport(entries=[e])
    assert r.find("my_pkg") is e


def test_age_report_find_returns_none_when_missing():
    r = AgeReport(entries=[])
    assert r.find("nonexistent") is None


# ---------------------------------------------------------------------------
# _fetch_release_date
# ---------------------------------------------------------------------------

def test_fetch_release_date_returns_datetime():
    dep = _dep()
    sess = _mock_session("2020-06-15T12:00:00Z")
    result = _fetch_release_date(dep, session=sess)
    assert isinstance(result, datetime)
    assert result.year == 2020


def test_fetch_release_date_returns_none_on_error():
    dep = _dep()
    sess = MagicMock()
    sess.get.side_effect = Exception("network error")
    result = _fetch_release_date(dep, session=sess)
    assert result is None


def test_fetch_release_date_returns_none_when_no_files():
    dep = _dep()
    sess = MagicMock()
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"releases": {"2.28.0": []}}
    sess.get.return_value = resp
    result = _fetch_release_date(dep, session=sess)
    assert result is None


# ---------------------------------------------------------------------------
# _age_entry
# ---------------------------------------------------------------------------

def test_age_entry_is_old_when_over_threshold():
    dep = _dep()
    old_date = datetime.now(timezone.utc) - timedelta(days=_OLD_THRESHOLD_DAYS + 10)
    sess = _mock_session(old_date.isoformat())
    entry = _age_entry(dep, session=sess)
    assert entry.is_old is True


def test_age_entry_is_fresh_when_under_threshold():
    dep = _dep()
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)
    sess = _mock_session(recent_date.isoformat())
    entry = _age_entry(dep, session=sess)
    assert entry.is_old is False


# ---------------------------------------------------------------------------
# build_age_report
# ---------------------------------------------------------------------------

def test_build_age_report_deduplicates():
    dep = _dep()
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)
    sess = _mock_session(recent_date.isoformat())
    age_report = build_age_report(report, session=sess)
    assert age_report.total == 1


def test_build_age_report_total_matches_unique_deps():
    dep1 = _dep("requests", "2.28.0")
    dep2 = _dep("flask", "2.0.0")
    report = _report(dep1, dep2)
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)
    sess = _mock_session(recent_date.isoformat())
    age_report = build_age_report(report, session=sess)
    assert age_report.total == 2
