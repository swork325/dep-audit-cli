"""Tests for dep_audit.auditor_maturity and dep_audit.cli_maturity."""
from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_maturity import (
    MaturityEntry,
    MaturityReport,
    _assess,
    build_maturity_report,
)
from dep_audit.cli_maturity import (
    _render_json,
    _render_text,
    add_maturity_args,
    maybe_render_maturity,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str = "requests", current: str = "2.28.0", latest: str = "2.31.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# _assess
# ---------------------------------------------------------------------------

def test_assess_no_releases_is_immature():
    mature, reason = _assess(None, 0)
    assert not mature
    assert "no release data" in reason


def test_assess_few_releases_is_immature():
    old = datetime.now(timezone.utc) - timedelta(days=400)
    mature, reason = _assess(old, 3)
    assert not mature
    assert "3 release" in reason


def test_assess_young_project_is_immature():
    young = datetime.now(timezone.utc) - timedelta(days=30)
    mature, reason = _assess(young, 10)
    assert not mature
    assert "days old" in reason


def test_assess_mature_project():
    old = datetime.now(timezone.utc) - timedelta(days=500)
    mature, reason = _assess(old, 20)
    assert mature
    assert "sufficient" in reason


# ---------------------------------------------------------------------------
# MaturityReport helpers
# ---------------------------------------------------------------------------

def _entry(name: str, mature: bool) -> MaturityEntry:
    return MaturityEntry(
        name=name,
        current_version="1.0.0",
        first_release_date=None,
        total_releases=10 if mature else 1,
        is_mature=mature,
        reason="ok" if mature else "too few",
    )


def test_maturity_report_total():
    r = MaturityReport(entries=[_entry("a", True), _entry("b", False)])
    assert r.total == 2


def test_maturity_report_immature_count():
    r = MaturityReport(entries=[_entry("a", True), _entry("b", False), _entry("c", False)])
    assert r.immature_count == 2


def test_maturity_report_find_normalises_hyphens():
    r = MaturityReport(entries=[_entry("my-pkg", True)])
    assert r.find("my_pkg") is not None


def test_maturity_report_find_returns_none_when_missing():
    r = MaturityReport(entries=[])
    assert r.find("unknown") is None


def test_entry_to_dict_keys():
    e = _entry("requests", True)
    d = e.to_dict()
    assert set(d.keys()) == {
        "name", "current_version", "first_release_date",
        "total_releases", "is_mature", "reason",
    }


# ---------------------------------------------------------------------------
# build_maturity_report (mocked HTTP)
# ---------------------------------------------------------------------------

def _mock_session(first_iso: str = "2019-01-01T00:00:00Z", total_versions: int = 20):
    session = MagicMock()
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    releases = {
        str(i): [{"upload_time_iso_8601": first_iso if i == 1 else "2022-06-01T00:00:00Z"}]
        for i in range(1, total_versions + 1)
    }
    resp.json.return_value = {"releases": releases}
    session.get.return_value = resp
    return session


def test_build_maturity_report_creates_entry_per_unique_dep():
    dep1 = _dep("requests")
    dep2 = _dep("flask")
    report = _report(dep1, dep2)
    session = _mock_session()
    mat = build_maturity_report(report, session=session)
    assert mat.total == 2


def test_build_maturity_report_deduplicates():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    session = _mock_session()
    mat = build_maturity_report(report, session=session)
    assert mat.total == 1


def test_build_maturity_report_marks_mature_correctly():
    dep = _dep("requests")
    report = _report(dep)
    session = _mock_session(first_iso="2018-01-01T00:00:00Z", total_versions=30)
    mat = build_maturity_report(report, session=session)
    entry = mat.find("requests")
    assert entry is not None
    assert entry.is_mature


def test_build_maturity_report_on_http_error():
    dep = _dep("requests")
    report = _report(dep)
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    mat = build_maturity_report(report, session=session)
    entry = mat.find("requests")
    assert entry is not None
    assert not entry.is_mature


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

def _mat_report() -> MaturityReport:
    return MaturityReport(
        entries=[
            _entry("requests", True),
            _entry("newpkg", False),
        ]
    )


def test_render_text_contains_header():
    text = _render_text(_mat_report(), immature_only=False)
    assert "Maturity Report" in text


def test_render_text_immature_only_excludes_mature():
    text = _render_text(_mat_report(), immature_only=True)
    assert "newpkg" in text
    assert "requests" not in text


def test_render_json_structure():
    data = json.loads(_render_json(_mat_report(), immature_only=False))
    assert "total" in data
    assert "immature_count" in data
    assert "entries" in data
    assert len(data["entries"]) == 2


def test_render_json_immature_only():
    data = json.loads(_render_json(_mat_report(), immature_only=True))
    assert len(data["entries"]) == 1
    assert data["entries"][0]["name"] == "newpkg"


def _parse(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_maturity_args(parser)
    return parser.parse_args(args)


def test_defaults():
    ns = _parse([])
    assert ns.maturity is False
    assert ns.maturity_format == "text"
    assert ns.maturity_immature_only is False


def test_maturity_flag():
    ns = _parse(["--maturity"])
    assert ns.maturity is True


def test_maybe_render_maturity_skips_when_not_requested():
    ns = _parse([])
    out = io.StringIO()
    report = _report(_dep())
    maybe_render_maturity(ns, report, session=MagicMock(), out=out)
    assert out.getvalue() == ""


def test_maybe_render_maturity_writes_text():
    ns = _parse(["--maturity"])
    out = io.StringIO()
    report = _report(_dep())
    session = _mock_session()
    maybe_render_maturity(ns, report, session=session, out=out)
    assert "Maturity Report" in out.getvalue()


def test_maybe_render_maturity_writes_json():
    ns = _parse(["--maturity", "--maturity-format", "json"])
    out = io.StringIO()
    report = _report(_dep())
    session = _mock_session()
    maybe_render_maturity(ns, report, session=session, out=out)
    data = json.loads(out.getvalue())
    assert "entries" in data
