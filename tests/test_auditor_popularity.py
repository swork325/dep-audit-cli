"""Tests for dep_audit.auditor_popularity."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor_popularity import (
    PopularityEntry,
    PopularityReport,
    build_popularity_report,
    fetch_popularity,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit


def _dep(name: str = "requests", version: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(name=name, version=version, latest=version, vulns=[])


def _mock_session(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    sess = MagicMock()
    sess.get.return_value = resp
    return sess


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# --- PopularityEntry ---

def test_popularity_entry_to_dict_keys():
    e = PopularityEntry(name="requests", version="2.28.0", last_month=1_000_000, last_week=250_000, last_day=35_000)
    d = e.to_dict()
    assert set(d.keys()) == {"name", "version", "last_month", "last_week", "last_day"}


def test_popularity_entry_to_dict_values():
    e = PopularityEntry(name="flask", version="3.0.0", last_month=500_000, last_week=120_000, last_day=18_000)
    d = e.to_dict()
    assert d["name"] == "flask"
    assert d["last_month"] == 500_000


# --- PopularityReport ---

def test_popularity_report_total():
    entries = [PopularityEntry("a", "1.0", 100, 20, 3), PopularityEntry("b", "2.0", 200, 40, 6)]
    pr = PopularityReport(entries=entries)
    assert pr.total == 2


def test_popularity_report_find_by_name():
    e = PopularityEntry("requests", "2.28.0", 1_000_000, 250_000, 35_000)
    pr = PopularityReport(entries=[e])
    found = pr.find("requests")
    assert found is e


def test_popularity_report_find_normalises_hyphens():
    e = PopularityEntry("my-pkg", "1.0", 100, 20, 3)
    pr = PopularityReport(entries=[e])
    assert pr.find("my_pkg") is e


def test_popularity_report_find_returns_none_when_missing():
    pr = PopularityReport(entries=[])
    assert pr.find("nonexistent") is None


def test_popularity_report_top_sorts_by_last_month():
    entries = [
        PopularityEntry("a", "1.0", 100, 20, 3),
        PopularityEntry("b", "2.0", 900, 40, 6),
        PopularityEntry("c", "3.0", 500, 10, 1),
    ]
    pr = PopularityReport(entries=entries)
    top2 = pr.top(2)
    assert [e.name for e in top2] == ["b", "c"]


def test_popularity_report_top_excludes_none_last_month():
    entries = [
        PopularityEntry("a", "1.0", None, None, None),
        PopularityEntry("b", "2.0", 900, 40, 6),
    ]
    pr = PopularityReport(entries=entries)
    top = pr.top(5)
    assert len(top) == 1 and top[0].name == "b"


# --- fetch_popularity ---

def test_fetch_popularity_returns_entry_on_success():
    dep = _dep("requests", "2.28.0")
    payload = {"data": {"last_month": 1_000_000, "last_week": 250_000, "last_day": 35_000}}
    sess = _mock_session(payload)
    entry = fetch_popularity(dep, session=sess)
    assert entry is not None
    assert entry.name == "requests"
    assert entry.last_month == 1_000_000


def test_fetch_popularity_returns_none_on_error():
    dep = _dep("requests")
    sess = MagicMock()
    sess.get.side_effect = Exception("network error")
    entry = fetch_popularity(dep, session=sess)
    assert entry is None


def test_fetch_popularity_hits_correct_url():
    dep = _dep("My_Package", "1.0")
    payload = {"data": {"last_month": 0, "last_week": 0, "last_day": 0}}
    sess = _mock_session(payload)
    fetch_popularity(dep, session=sess)
    call_url = sess.get.call_args[0][0]
    assert "my-package" in call_url


# --- build_popularity_report ---

def test_build_popularity_report_deduplicates_packages():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    payload = {"data": {"last_month": 100, "last_week": 20, "last_day": 3}}
    sess = _mock_session(payload)
    pop = build_popularity_report(report, session=sess)
    assert pop.total == 1


def test_build_popularity_report_skips_failed_fetches():
    dep = _dep("requests")
    report = _report(dep)
    sess = MagicMock()
    sess.get.side_effect = Exception("fail")
    pop = build_popularity_report(report, session=sess)
    assert pop.total == 0
