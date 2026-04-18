"""Tests for dep_audit.resolver."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep, fetch_latest_version, resolve_dependencies


# ---------------------------------------------------------------------------
# fetch_latest_version
# ---------------------------------------------------------------------------

def _mock_session(version: str) -> MagicMock:
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"info": {"version": version}}
    resp.raise_for_status.return_value = None
    session.get.return_value = resp
    return session


def test_fetch_latest_version_returns_version():
    session = _mock_session("2.28.2")
    result = fetch_latest_version("requests", session=session)
    assert result == "2.28.2"
    session.get.assert_called_once()


def test_fetch_latest_version_returns_none_on_error():
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    result = fetch_latest_version("nonexistent-pkg", session=session)
    assert result is None


def test_fetch_latest_version_normalizes_name():
    session = _mock_session("1.0.0")
    fetch_latest_version("My_Package", session=session)
    url = session.get.call_args[0][0]
    assert "my-package" in url


def test_fetch_latest_version_hits_pypi_url():
    """Ensure the PyPI JSON API endpoint is used for the lookup."""
    session = _mock_session("1.2.3")
    fetch_latest_version("requests", session=session)
    url = session.get.call_args[0][0]
    assert "pypi.org" in url
    assert "requests" in url
    assert "json" in url


# ---------------------------------------------------------------------------
# ResolvedDep.is_outdated
# ---------------------------------------------------------------------------

def test_is_outdated_true():
    dep = ResolvedDep("requests", ">=2.0", "2.27.0", "2.28.2")
    assert dep.is_outdated is True


def test_is_outdated_false_when_same():
    dep = ResolvedDep("requests", ">=2.0", "2.28.2", "2.28.2")
    assert dep.is_outdated is False


def test_is_outdated_false_when_no_installed():
    dep = ResolvedDep("requests", "", None, "2.28.2")
    assert dep.is_outdated is False


def test_is_outdated_false_when_no_latest():
    """If latest_version is unknown, is_outdated should not raise and return False."""
    dep = ResolvedDep("requests", ">=2.0", "2.27.0", None)
    assert dep.is_outdated is False


# ---------------------------------------------------------------------------
# resolve_dependencies
# ---------------------------------------------------------------------------

def test_resolve_dependencies_full(monkeypatch):
    session = _mock_session("3.0.0")

    monkeypatch.setattr(
        "importlib.metadata.version",
        lambda name: "2.0.0",
    )

    reqs = [{"name": "flask", "specifier": ">=1.0"}]
    results = resolve_dependencies(reqs, session=session)

    assert len(results) == 1
    dep = results[0]
    assert dep.name == "flask"
    assert dep.installed_version == "2.0.0"
    assert dep.latest_version == "3.0.0"
    assert dep.is_outdated is True


def test_resolve_dependencies_missing_package(monkeypatch):
    import importlib.metadata as meta

    session = _mock_session("1.0.0")
    monkeypatch.setattr(
        "importlib.metadata.version",
        MagicMock(side_effect=meta.PackageNotFoundError),
    )

    reqs = [{"name": "unknown-lib", "specifier": ""}]
    results = resolve_dependencies(reqs, session=session)

    assert results[0]
