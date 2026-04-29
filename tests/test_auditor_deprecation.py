"""Tests for dep_audit.auditor_deprecation."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor_deprecation import (
    DeprecationEntry,
    DeprecationReport,
    build_deprecation_report,
    check_deprecation,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str = "requests", current: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version="2.31.0",
        is_outdated=True,
        vulnerabilities=[],
    )


def _mock_session(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    sess = MagicMock()
    sess.get.return_value = resp
    return sess


def _pypi_payload(
    classifiers=None, keywords="", version="2.28.0", yanked=False
) -> dict:
    files = [{"yanked": yanked, "filename": f"{version}.tar.gz"}]
    return {
        "info": {
            "name": "requests",
            "version": version,
            "classifiers": classifiers or [],
            "keywords": keywords,
        },
        "releases": {version: files},
    }


# ---------------------------------------------------------------------------
# DeprecationEntry
# ---------------------------------------------------------------------------

def test_deprecation_entry_to_dict_keys():
    entry = DeprecationEntry(name="old-pkg", version="1.0.0", reason="classifier", detail="inactive")
    d = entry.to_dict()
    assert set(d.keys()) == {"name", "version", "reason", "detail"}


def test_deprecation_entry_to_dict_values():
    entry = DeprecationEntry(name="old-pkg", version="1.0.0", reason="keyword", detail="deprecated")
    d = entry.to_dict()
    assert d["reason"] == "keyword"
    assert d["detail"] == "deprecated"


# ---------------------------------------------------------------------------
# DeprecationReport
# ---------------------------------------------------------------------------

def test_deprecation_report_total():
    entries = [
        DeprecationEntry("a", "1.0", "classifier"),
        DeprecationEntry("b", "2.0", "keyword"),
    ]
    report = DeprecationReport(entries=entries)
    assert report.total == 2


def test_deprecation_report_find_by_name():
    entry = DeprecationEntry("requests", "2.28.0", "classifier")
    report = DeprecationReport(entries=[entry])
    assert report.find("requests") is entry


def test_deprecation_report_find_normalises_hyphens():
    entry = DeprecationEntry("my-pkg", "1.0", "keyword")
    report = DeprecationReport(entries=[entry])
    assert report.find("my_pkg") is entry


def test_deprecation_report_find_returns_none_when_missing():
    report = DeprecationReport(entries=[])
    assert report.find("unknown") is None


# ---------------------------------------------------------------------------
# check_deprecation
# ---------------------------------------------------------------------------

def test_check_deprecation_inactive_classifier():
    payload = _pypi_payload(classifiers=["Development Status :: 7 - Inactive"])
    sess = _mock_session(payload)
    result = check_deprecation(_dep(), sess)
    assert result is not None
    assert result.reason == "classifier"


def test_check_deprecation_deprecated_keyword():
    payload = _pypi_payload(keywords="deprecated, http")
    sess = _mock_session(payload)
    result = check_deprecation(_dep(), sess)
    assert result is not None
    assert result.reason == "keyword"


def test_check_deprecation_yanked_release():
    payload = _pypi_payload(yanked=True)
    sess = _mock_session(payload)
    result = check_deprecation(_dep(), sess)
    assert result is not None
    assert result.reason == "yanked"


def test_check_deprecation_clean_returns_none():
    payload = _pypi_payload()
    sess = _mock_session(payload)
    result = check_deprecation(_dep(), sess)
    assert result is None


def test_check_deprecation_returns_none_on_http_error():
    sess = _mock_session({}, status=404)
    result = check_deprecation(_dep(), sess)
    assert result is None


# ---------------------------------------------------------------------------
# build_deprecation_report
# ---------------------------------------------------------------------------

def test_build_deprecation_report_collects_deprecated_deps():
    payload = _pypi_payload(classifiers=["Development Status :: 7 - Inactive"])
    sess = _mock_session(payload)
    deps = [_dep("requests"), _dep("flask")]
    report = build_deprecation_report(deps, session=sess)
    assert report.total == 2


def test_build_deprecation_report_empty_when_all_clean():
    payload = _pypi_payload()
    sess = _mock_session(payload)
    deps = [_dep("requests")]
    report = build_deprecation_report(deps, session=sess)
    assert report.total == 0
