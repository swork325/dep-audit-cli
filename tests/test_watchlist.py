"""Tests for dep_audit.watchlist."""
import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.watchlist import (
    filter_by_watchlist,
    is_watched,
    load_watchlist,
    save_watchlist,
)


def _dep(name: str, installed: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, installed=installed, latest=latest, vulns=[])


def test_load_returns_empty_when_missing(tmp_path):
    result = load_watchlist(str(tmp_path / "missing.json"))
    assert result == []


def test_load_returns_empty_on_invalid_json(tmp_path):
    f = tmp_path / "wl.json"
    f.write_text("not-json")
    assert load_watchlist(str(f)) == []


def test_load_returns_normalised_names(tmp_path):
    f = tmp_path / "wl.json"
    f.write_text(json.dumps(["Requests", "Flask"]))
    result = load_watchlist(str(f))
    assert "requests" in result
    assert "flask" in result


def test_save_and_reload(tmp_path):
    f = tmp_path / "wl.json"
    save_watchlist(["Django", "requests"], str(f))
    loaded = load_watchlist(str(f))
    assert "django" in loaded
    assert "requests" in loaded


def test_save_deduplicates(tmp_path):
    f = tmp_path / "wl.json"
    save_watchlist(["requests", "Requests"], str(f))
    loaded = load_watchlist(str(f))
    assert loaded.count("requests") == 1


def test_is_watched_true():
    dep = _dep("requests")
    assert is_watched(dep, ["requests", "flask"]) is True


def test_is_watched_case_insensitive():
    dep = _dep("Requests")
    assert is_watched(dep, ["requests"]) is True


def test_is_watched_false():
    dep = _dep("boto3")
    assert is_watched(dep, ["requests", "flask"]) is False


def test_filter_by_watchlist_keeps_only_watched():
    fa = FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask"), _dep("boto3")])
    report = AuditReport(files=[fa])
    result = filter_by_watchlist(report, ["requests", "flask"])
    assert len(result.files) == 1
    names = [d.name for d in result.files[0].deps]
    assert "boto3" not in names
    assert "requests" in names


def test_filter_by_watchlist_excludes_empty_files():
    fa = FileAudit(path="req.txt", deps=[_dep("boto3")])
    report = AuditReport(files=[fa])
    result = filter_by_watchlist(report, ["requests"])
    assert result.files == []
