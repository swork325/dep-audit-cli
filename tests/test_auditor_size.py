"""Tests for dep_audit.auditor_size."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor_size import (
    SizeEntry,
    SizeReport,
    _fetch_size,
    _assess,
    build_size_report,
    _LARGE_BYTES,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.vulnerability import VulnResult


def _dep(name="requests", current="2.28.0", latest="2.31.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current=current,
        latest=latest,
        outdated=latest != current,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _mock_session(size: int = 5_000_000):
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {
        "releases": {
            "2.28.0": [{"size": size}]
        }
    }
    resp.raise_for_status = MagicMock()
    session.get.return_value = resp
    return session


def test_size_entry_to_dict_keys():
    e = SizeEntry(name="requests", version="2.28.0", size_bytes=1024, is_large=False)
    assert set(e.to_dict().keys()) == {"name", "version", "size_bytes", "is_large"}


def test_size_entry_to_dict_values():
    e = SizeEntry(name="requests", version="2.28.0", size_bytes=1024, is_large=False)
    d = e.to_dict()
    assert d["name"] == "requests"
    assert d["size_bytes"] == 1024
    assert d["is_large"] is False


def test_size_report_total():
    r = SizeReport(entries=[
        SizeEntry("a", "1.0", 100, False),
        SizeEntry("b", "2.0", 20_000_000, True),
    ])
    assert r.total == 2


def test_size_report_large_count():
    r = SizeReport(entries=[
        SizeEntry("a", "1.0", 100, False),
        SizeEntry("b", "2.0", 20_000_000, True),
        SizeEntry("c", "3.0", 15_000_000, True),
    ])
    assert r.large_count == 2


def test_size_report_find_by_name():
    r = SizeReport(entries=[SizeEntry("requests", "2.28.0", 500, False)])
    assert r.find("requests") is not None
    assert r.find("missing") is None


def test_size_report_find_normalises_hyphens():
    r = SizeReport(entries=[SizeEntry("my_pkg", "1.0", 100, False)])
    assert r.find("my-pkg") is not None


def test_fetch_size_returns_total():
    session = _mock_session(size=3_000_000)
    result = _fetch_size("requests", "2.28.0", session)
    assert result == 3_000_000


def test_fetch_size_returns_none_on_error():
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    assert _fetch_size("requests", "2.28.0", session) is None


def test_assess_is_large_when_above_threshold():
    session = _mock_session(size=_LARGE_BYTES + 1)
    entry = _assess("requests", "2.28.0", session)
    assert entry.is_large is True


def test_assess_not_large_when_below_threshold():
    session = _mock_session(size=1024)
    entry = _assess("requests", "2.28.0", session)
    assert entry.is_large is False


def test_build_size_report_deduplicates():
    dep = _dep()
    fa = FileAudit(path="req.txt", deps=[dep, dep])
    report = AuditReport(files=[fa])
    session = _mock_session()
    sr = build_size_report(report, session=session)
    assert sr.total == 1


def test_build_size_report_uses_latest_when_available():
    dep = _dep(latest="2.31.0")
    fa = FileAudit(path="req.txt", deps=[dep])
    report = AuditReport(files=[fa])
    session = _mock_session()
    build_size_report(report, session=session)
    call_url = session.get.call_args[0][0]
    assert "requests" in call_url
