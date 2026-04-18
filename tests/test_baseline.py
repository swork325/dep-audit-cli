"""Tests for dep_audit.baseline."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.baseline import save_baseline, load_baseline, diff_baseline, DEFAULT_BASELINE


def _make_dep(name, current, latest, vuln_ids=None):
    d = MagicMock()
    d.name = name
    d.current_version = current
    d.latest_version = latest
    d.vulnerabilities = [MagicMock(vuln_id=v) for v in (vuln_ids or [])]
    return d


@pytest.fixture()
def report():
    fa = MagicMock()
    fa.path = "requirements.txt"
    fa.deps = [
        _make_dep("requests", "2.28.0", "2.31.0"),
        _make_dep("flask", "2.0.0", "2.0.0"),
        _make_dep("pillow", "9.0.0", "9.5.0", vuln_ids=["GHSA-1234"]),
    ]
    r = MagicMock()
    r.file_audits = [fa]
    return r


def test_save_baseline_creates_file(tmp_path, report):
    dest = tmp_path / "baseline.json"
    save_baseline(report, dest)
    assert dest.exists()
    data = json.loads(dest.read_text())
    assert "requirements.txt" in data


def test_save_baseline_records_deps(tmp_path, report):
    dest = tmp_path / "baseline.json"
    save_baseline(report, dest)
    data = json.loads(dest.read_text())
    names = [d["name"] for d in data["requirements.txt"]]
    assert "requests" in names
    assert "flask" in names


def test_load_baseline_returns_none_when_missing(tmp_path):
    result = load_baseline(tmp_path / "nonexistent.json")
    assert result is None


def test_load_baseline_round_trips(tmp_path, report):
    dest = tmp_path / "baseline.json"
    save_baseline(report, dest)
    loaded = load_baseline(dest)
    assert isinstance(loaded, dict)
    assert "requirements.txt" in loaded


def test_diff_baseline_detects_new_issue(report):
    # baseline has no issues for requests
    baseline = {
        "requirements.txt": [
            {"name": "requests", "current": "2.28.0", "latest": "2.28.0", "vulns": []},
            {"name": "flask", "current": "2.0.0", "latest": "2.0.0", "vulns": []},
            {"name": "pillow", "current": "9.0.0", "latest": "9.0.0", "vulns": []},
        ]
    }
    new_issues = diff_baseline(report, baseline)
    assert "requirements.txt" in new_issues
    assert "requests" in new_issues["requirements.txt"]
    assert "pillow" in new_issues["requirements.txt"]


def test_diff_baseline_no_new_issues_when_already_known(report):
    baseline = {
        "requirements.txt": [
            {"name": "requests", "current": "2.28.0", "latest": "2.31.0", "vulns": []},
            {"name": "flask", "current": "2.0.0", "latest": "2.0.0", "vulns": []},
            {"name": "pillow", "current": "9.0.0", "latest": "9.5.0", "vulns": ["GHSA-1234"]},
        ]
    }
    new_issues = diff_baseline(report, baseline)
    assert new_issues == {}
