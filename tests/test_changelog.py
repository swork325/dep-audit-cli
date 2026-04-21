"""Tests for dep_audit.changelog."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.changelog import (
    ChangelogEntry,
    _extract_changelog_url,
    build_changelog_entries,
    fetch_changelog_url,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dep(name: str, *, outdated: bool = False, current: str = "1.0.0", latest: str = "2.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current=current,
        latest=latest if outdated else current,
        outdated=outdated,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _mock_session(project_urls: dict | None = None, raise_error: bool = False) -> MagicMock:
    sess = MagicMock()
    if raise_error:
        sess.get.side_effect = Exception("network error")
    else:
        resp = MagicMock()
        resp.json.return_value = {"info": {"project_urls": project_urls or {}}}
        resp.raise_for_status.return_value = None
        sess.get.return_value = resp
    return sess


@pytest.fixture()
def report() -> AuditReport:
    deps = [
        _dep("requests", outdated=True),
        _dep("flask", outdated=False),
        _dep("click", outdated=True),
    ]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# _extract_changelog_url
# ---------------------------------------------------------------------------

def test_extract_changelog_url_finds_changelog_key():
    info = {"project_urls": {"Changelog": "https://example.com/changelog"}}
    assert _extract_changelog_url(info) == "https://example.com/changelog"


def test_extract_changelog_url_finds_release_notes():
    info = {"project_urls": {"Release notes": "https://example.com/releases"}}
    assert _extract_changelog_url(info) == "https://example.com/releases"


def test_extract_changelog_url_returns_none_when_absent():
    info = {"project_urls": {"Homepage": "https://example.com"}}
    assert _extract_changelog_url(info) is None


def test_extract_changelog_url_handles_missing_project_urls():
    assert _extract_changelog_url({}) is None


# ---------------------------------------------------------------------------
# fetch_changelog_url
# ---------------------------------------------------------------------------

def test_fetch_changelog_url_returns_url():
    sess = _mock_session({"Changelog": "https://example.com/changelog"})
    result = fetch_changelog_url("requests", session=sess)
    assert result == "https://example.com/changelog"


def test_fetch_changelog_url_returns_none_on_error():
    sess = _mock_session(raise_error=True)
    result = fetch_changelog_url("requests", session=sess)
    assert result is None


def test_fetch_changelog_url_hits_correct_endpoint():
    sess = _mock_session()
    fetch_changelog_url("requests", session=sess)
    call_url = sess.get.call_args[0][0]
    assert "requests" in call_url
    assert "pypi.org" in call_url


# ---------------------------------------------------------------------------
# build_changelog_entries
# ---------------------------------------------------------------------------

def test_build_changelog_entries_outdated_only(report):
    sess = _mock_session({"Changelog": "https://example.com"})
    entries = build_changelog_entries(report, outdated_only=True, session=sess)
    names = {e.package for e in entries}
    assert "flask" not in names
    assert "requests" in names
    assert "click" in names


def test_build_changelog_entries_all_deps(report):
    sess = _mock_session()
    entries = build_changelog_entries(report, outdated_only=False, session=sess)
    assert len(entries) == 3


def test_build_changelog_entries_deduplicates_packages():
    dep = _dep("requests", outdated=True)
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    r = AuditReport(files=[fa1, fa2])
    sess = _mock_session()
    entries = build_changelog_entries(r, session=sess)
    assert len(entries) == 1


def test_changelog_entry_has_url_property():
    e_with = ChangelogEntry(package="requests", version="2.0.0", url="https://x.com")
    e_without = ChangelogEntry(package="flask", version="1.0.0", url=None)
    assert e_with.has_url is True
    assert e_without.has_url is False
