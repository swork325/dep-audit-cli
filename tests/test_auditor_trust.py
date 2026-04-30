"""Tests for dep_audit.auditor_trust and dep_audit.cli_trust."""
from __future__ import annotations

import json
import argparse
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.auditor_trust import (
    TrustEntry,
    TrustReport,
    _assess_trust,
    build_trust_report,
)
from dep_audit.cli_trust import (
    add_trust_args,
    _render_text,
    _render_json,
    maybe_render_trust,
)


def _dep(name: str = "requests", version: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=version, latest_version=version, vulns=[])


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def _entry(trusted: bool = True, releases: int = 10) -> TrustEntry:
    return TrustEntry(
        name="requests",
        version="2.28.0",
        monthly_downloads=None,
        release_count=releases,
        trusted=trusted,
        reason="meets trust thresholds" if trusted else "only 1 release(s) on PyPI",
    )


# --- _assess_trust ---

def test_assess_trust_trusted_when_enough_releases():
    trusted, reason = _assess_trust(release_count=10, monthly_downloads=None)
    assert trusted is True
    assert "meets" in reason


def test_assess_trust_untrusted_when_few_releases():
    trusted, reason = _assess_trust(release_count=1, monthly_downloads=None)
    assert trusted is False
    assert "1" in reason


def test_assess_trust_untrusted_when_low_downloads():
    trusted, reason = _assess_trust(release_count=5, monthly_downloads=50)
    assert trusted is False
    assert "50" in reason


def test_assess_trust_trusted_when_downloads_above_threshold():
    trusted, _ = _assess_trust(release_count=5, monthly_downloads=5_000)
    assert trusted is True


# --- TrustReport ---

def test_trust_report_total():
    tr = TrustReport(entries=[_entry(), _entry(trusted=False)])
    assert tr.total() == 2


def test_trust_report_untrusted_count():
    tr = TrustReport(entries=[_entry(trusted=True), _entry(trusted=False), _entry(trusted=False)])
    assert tr.untrusted_count() == 2


def test_trust_report_find_normalises_hyphens():
    e = TrustEntry(name="my-pkg", version="1.0", monthly_downloads=None, release_count=5, trusted=True, reason="ok")
    tr = TrustReport(entries=[e])
    assert tr.find("my_pkg") is e


def test_trust_report_find_returns_none_when_missing():
    tr = TrustReport(entries=[])
    assert tr.find("unknown") is None


# --- build_trust_report ---

def _mock_session(release_count: int = 10) -> MagicMock:
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"releases": {str(i): [] for i in range(release_count)}}
    resp.raise_for_status = MagicMock()
    session.get.return_value = resp
    return session


def test_build_trust_report_creates_entry_per_unique_dep():
    report = _report(_dep("requests"), _dep("flask", "2.0.0"))
    tr = build_trust_report(report, session=_mock_session())
    assert tr.total() == 2


def test_build_trust_report_deduplicates_across_files():
    dep = _dep("requests")
    fa1 = FileAudit(path="req.txt", deps=[dep])
    fa2 = FileAudit(path="dev.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    tr = build_trust_report(report, session=_mock_session())
    assert tr.total() == 1


def test_build_trust_report_marks_low_release_as_untrusted():
    report = _report(_dep("newpkg"))
    tr = build_trust_report(report, session=_mock_session(release_count=1))
    assert tr.untrusted_count() == 1


def test_build_trust_report_on_session_error_release_count_zero():
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    report = _report(_dep("requests"))
    tr = build_trust_report(report, session=session)
    assert tr.entries[0].release_count == 0
    assert tr.entries[0].trusted is False


# --- render helpers ---

def test_render_text_shows_trusted_status():
    tr = TrustReport(entries=[_entry(trusted=True)])
    text = _render_text(tr, only_untrusted=False)
    assert "TRUSTED" in text


def test_render_text_only_untrusted_filters():
    tr = TrustReport(entries=[_entry(trusted=True), _entry(trusted=False)])
    text = _render_text(tr, only_untrusted=True)
    assert "UNTRUSTED" in text
    assert text.count("requests") == 1


def test_render_json_structure():
    tr = TrustReport(entries=[_entry()])
    data = json.loads(_render_json(tr, only_untrusted=False))
    assert "total" in data
    assert "untrusted_count" in data
    assert "entries" in data


# --- CLI ---

def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_trust_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.trust is False
    assert ns.trust_format == "text"
    assert ns.trust_only_untrusted is False


def test_trust_flag():
    ns = _parse("--trust")
    assert ns.trust is True


def test_trust_format_json():
    ns = _parse("--trust-format", "json")
    assert ns.trust_format == "json"


def test_maybe_render_trust_skips_when_flag_false(capsys):
    ns = _parse()
    maybe_render_trust(ns, _report(_dep()), session=_mock_session())
    assert capsys.readouterr().out == ""


def test_maybe_render_trust_prints_when_flag_set(capsys):
    ns = _parse("--trust")
    maybe_render_trust(ns, _report(_dep()), session=_mock_session())
    out = capsys.readouterr().out
    assert "Trust" in out
