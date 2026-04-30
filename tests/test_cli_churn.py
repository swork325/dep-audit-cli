"""Tests for dep_audit.cli_churn."""
from __future__ import annotations

import argparse
import io
import json
import os

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_churn import (
    _load_history,
    _save_history,
    _update_history,
    _render_text,
    _render_json,
    add_churn_args,
    maybe_render_churn,
)
from dep_audit.auditor_churn import ChurnEntry, ChurnReport
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, current: str = "1.0.0", latest: str = "2.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulnerabilities=VulnResult(package=name, vulns=[]),
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def _parse(args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_churn_args(p)
    return p.parse_args(args)


# --- add_churn_args defaults ---

def test_defaults():
    ns = _parse([])
    assert ns.churn is False
    assert ns.churn_threshold == 3
    assert ns.churn_format == "text"


def test_churn_flag_sets_true():
    ns = _parse(["--churn"])
    assert ns.churn is True


def test_churn_threshold_custom():
    ns = _parse(["--churn-threshold", "5"])
    assert ns.churn_threshold == 5


def test_churn_format_json():
    ns = _parse(["--churn-format", "json"])
    assert ns.churn_format == "json"


# --- _load_history / _save_history ---

def test_load_history_missing_file_returns_empty(tmp_path):
    result = _load_history(str(tmp_path / "nope.json"))
    assert result == {}


def test_save_and_load_history_roundtrip(tmp_path):
    path = str(tmp_path / "churn.json")
    _save_history(path, {"requests": 4, "flask": 2})
    loaded = _load_history(path)
    assert loaded["requests"] == 4
    assert loaded["flask"] == 2


# --- _update_history ---

def test_update_history_increments_when_outdated():
    entry = ChurnEntry("requests", "2.0", "3.0", 1, False)
    cr = ChurnReport(entries=[entry])
    updated = _update_history({}, cr)
    assert updated.get("requests") == 1


def test_update_history_no_increment_when_current():
    entry = ChurnEntry("requests", "3.0", "3.0", 0, False)
    cr = ChurnReport(entries=[entry])
    updated = _update_history({}, cr)
    assert updated.get("requests", 0) == 0


# --- render helpers ---

def test_render_text_contains_header():
    cr = ChurnReport(entries=[])
    text = _render_text(cr)
    assert "Churn" in text


def test_render_text_shows_frequent_flag():
    entry = ChurnEntry("flask", "1.0", "2.0", 5, True)
    cr = ChurnReport(entries=[entry])
    text = _render_text(cr)
    assert "FREQUENT" in text


def test_render_json_is_valid():
    entry = ChurnEntry("flask", "1.0", "2.0", 5, True)
    cr = ChurnReport(entries=[entry])
    data = json.loads(_render_json(cr))
    assert "entries" in data
    assert data["total"] == 1


# --- maybe_render_churn ---

def test_maybe_render_churn_skipped_when_flag_false(tmp_path):
    ns = _parse([])
    ns.churn_history = str(tmp_path / "h.json")
    out = io.StringIO()
    result = maybe_render_churn(ns, _report(_dep("requests")), out=out)
    assert result is None
    assert out.getvalue() == ""


def test_maybe_render_churn_produces_output(tmp_path):
    ns = _parse(["--churn"])
    ns.churn_history = str(tmp_path / "h.json")
    out = io.StringIO()
    result = maybe_render_churn(ns, _report(_dep("requests")), out=out)
    assert result is not None
    assert len(out.getvalue()) > 0


def test_maybe_render_churn_updates_history_file(tmp_path):
    ns = _parse(["--churn"])
    hist_path = str(tmp_path / "h.json")
    ns.churn_history = hist_path
    maybe_render_churn(ns, _report(_dep("requests", "1.0", "2.0")), out=io.StringIO())
    assert os.path.exists(hist_path)
    history = _load_history(hist_path)
    assert "requests" in history
