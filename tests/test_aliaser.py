"""Tests for dep_audit.aliaser."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.aliaser import (
    DEFAULT_ALIASES,
    alias_report,
    load_alias_map,
    resolve_alias,
    save_alias_map,
)
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


# ---------------------------------------------------------------------------
# load_alias_map
# ---------------------------------------------------------------------------

def test_load_returns_defaults_when_no_file():
    result = load_alias_map(None)
    assert result == DEFAULT_ALIASES


def test_load_merges_user_file(tmp_path: Path):
    p = tmp_path / "aliases.json"
    p.write_text(json.dumps({"mylib": "my-library"}))
    result = load_alias_map(p)
    assert result["mylib"] == "my-library"
    assert "pillow" in result  # default still present


def test_load_returns_defaults_on_invalid_json(tmp_path: Path):
    p = tmp_path / "aliases.json"
    p.write_text("not-json")
    result = load_alias_map(p)
    assert result == DEFAULT_ALIASES


def test_load_normalises_keys_to_lowercase(tmp_path: Path):
    p = tmp_path / "aliases.json"
    p.write_text(json.dumps({"MyLib": "my-library"}))
    result = load_alias_map(p)
    assert "mylib" in result


# ---------------------------------------------------------------------------
# save_alias_map
# ---------------------------------------------------------------------------

def test_save_and_reload(tmp_path: Path):
    p = tmp_path / "aliases.json"
    save_alias_map({"foo": "bar"}, p)
    data = json.loads(p.read_text())
    assert data["foo"] == "bar"


# ---------------------------------------------------------------------------
# resolve_alias
# ---------------------------------------------------------------------------

def test_resolve_known_alias():
    assert resolve_alias("pillow", DEFAULT_ALIASES) == "Pillow"


def test_resolve_unknown_returns_original():
    assert resolve_alias("requests", DEFAULT_ALIASES) == "requests"


def test_resolve_case_insensitive():
    assert resolve_alias("PIL", DEFAULT_ALIASES) == "Pillow"


# ---------------------------------------------------------------------------
# alias_report
# ---------------------------------------------------------------------------

def test_alias_report_remaps_dep_name():
    dep = _dep("pillow")
    fa = FileAudit(path="requirements.txt", deps=[dep])
    report = AuditReport(files=[fa])
    result = alias_report(report, DEFAULT_ALIASES)
    assert result.files[0].deps[0].name == "Pillow"


def test_alias_report_leaves_unknown_unchanged():
    dep = _dep("requests")
    fa = FileAudit(path="requirements.txt", deps=[dep])
    report = AuditReport(files=[fa])
    result = alias_report(report, DEFAULT_ALIASES)
    assert result.files[0].deps[0].name == "requests"


def test_alias_report_preserves_version():
    dep = _dep("bs4", current="4.12.0", latest="4.12.3")
    fa = FileAudit(path="requirements.txt", deps=[dep])
    report = AuditReport(files=[fa])
    result = alias_report(report, DEFAULT_ALIASES)
    remapped = result.files[0].deps[0]
    assert remapped.current_version == "4.12.0"
    assert remapped.latest_version == "4.12.3"
