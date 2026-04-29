"""Tests for dep_audit.auditor_meta."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_meta import (
    PackageMeta,
    MetaReport,
    fetch_meta,
    build_meta_report,
)


def _dep(name: str, pinned: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, pinned=pinned, latest=latest, current=True, vulns=[])


def _mock_session(info: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"info": info}
    resp.raise_for_status = MagicMock()
    sess = MagicMock()
    sess.get.return_value = resp
    return sess


# ---------------------------------------------------------------------------
# PackageMeta
# ---------------------------------------------------------------------------

def test_package_meta_to_dict_keys():
    m = PackageMeta(name="requests", version="2.28.0", summary="HTTP", home_page="https://example.com", author="Alice", license="MIT")
    d = m.to_dict()
    assert set(d.keys()) == {"name", "version", "summary", "home_page", "author", "license"}


def test_package_meta_to_dict_values():
    m = PackageMeta(name="flask", version="3.0.0", summary=None, home_page=None, author=None, license=None)
    d = m.to_dict()
    assert d["name"] == "flask"
    assert d["summary"] is None


# ---------------------------------------------------------------------------
# MetaReport
# ---------------------------------------------------------------------------

def test_meta_report_total():
    r = MetaReport(entries=[PackageMeta("a", "1.0"), PackageMeta("b", "2.0")])
    assert r.total == 2


def test_meta_report_find_by_name():
    r = MetaReport(entries=[PackageMeta("requests", "2.28.0")])
    assert r.find("requests") is not None


def test_meta_report_find_normalises_hyphens():
    r = MetaReport(entries=[PackageMeta("my_pkg", "1.0")])
    assert r.find("my-pkg") is not None


def test_meta_report_find_returns_none_when_missing():
    r = MetaReport(entries=[])
    assert r.find("unknown") is None


def test_meta_report_with_home_page():
    r = MetaReport(entries=[
        PackageMeta("a", "1.0", home_page="https://a.com"),
        PackageMeta("b", "2.0", home_page=None),
    ])
    assert len(r.with_home_page()) == 1


# ---------------------------------------------------------------------------
# fetch_meta
# ---------------------------------------------------------------------------

def test_fetch_meta_returns_package_meta():
    dep = _dep("requests", pinned="2.28.0")
    sess = _mock_session({"summary": "HTTP", "home_page": "https://r.org", "author": "Alice", "license": "MIT"})
    result = fetch_meta(dep, session=sess)
    assert isinstance(result, PackageMeta)
    assert result.name == "requests"
    assert result.version == "2.28.0"
    assert result.summary == "HTTP"


def test_fetch_meta_returns_none_on_error():
    dep = _dep("broken", pinned="0.1.0")
    sess = MagicMock()
    sess.get.side_effect = Exception("network error")
    assert fetch_meta(dep, session=sess) is None


def test_fetch_meta_returns_none_when_no_version():
    dep = ResolvedDep(name="pkg", pinned=None, latest=None, current=True, vulns=[])
    assert fetch_meta(dep) is None


def test_fetch_meta_uses_latest_when_no_pin():
    dep = ResolvedDep(name="flask", pinned=None, latest="3.0.0", current=True, vulns=[])
    sess = _mock_session({"summary": "Web", "home_page": None, "author": None, "license": None})
    result = fetch_meta(dep, session=sess)
    assert result is not None
    assert result.version == "3.0.0"
    call_url = sess.get.call_args[0][0]
    assert "3.0.0" in call_url


# ---------------------------------------------------------------------------
# build_meta_report
# ---------------------------------------------------------------------------

def test_build_meta_report_deduplicates():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    with patch("dep_audit.auditor_meta.fetch_meta") as mock_fetch:
        mock_fetch.return_value = PackageMeta("requests", "1.0.0")
        result = build_meta_report(report)
    assert mock_fetch.call_count == 1
    assert result.total == 1


def test_build_meta_report_skips_none_results():
    dep = _dep("broken")
    fa = FileAudit(path="req.txt", deps=[dep])
    report = AuditReport(files=[fa])
    with patch("dep_audit.auditor_meta.fetch_meta", return_value=None):
        result = build_meta_report(report)
    assert result.total == 0
