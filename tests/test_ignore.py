"""Tests for dep_audit.ignore."""
import json
from pathlib import Path

import pytest

from dep_audit.ignore import (
    apply_ignore,
    is_ignored,
    load_ignore_list,
    save_ignore_list,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, installed: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, installed=installed, latest=latest, vulns=[])


# ---------------------------------------------------------------------------
# load_ignore_list
# ---------------------------------------------------------------------------

def test_load_returns_empty_when_file_missing(tmp_path):
    result = load_ignore_list(str(tmp_path / "nonexistent.json"))
    assert result == set()


def test_load_returns_package_names(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    ignore_file.write_text(json.dumps(["requests", "boto3"]))
    result = load_ignore_list(str(ignore_file))
    assert result == {"requests", "boto3"}


def test_load_normalises_to_lowercase(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    ignore_file.write_text(json.dumps(["Requests", "BOTO3"]))
    result = load_ignore_list(str(ignore_file))
    assert "requests" in result
    assert "boto3" in result


def test_load_returns_empty_on_invalid_json(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    ignore_file.write_text("not json")
    assert load_ignore_list(str(ignore_file)) == set()


def test_load_returns_empty_when_root_is_not_list(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    ignore_file.write_text(json.dumps({"requests": True}))
    assert load_ignore_list(str(ignore_file)) == set()


# ---------------------------------------------------------------------------
# save_ignore_list
# ---------------------------------------------------------------------------

def test_save_creates_file(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    save_ignore_list(["requests"], str(ignore_file))
    assert ignore_file.exists()


def test_save_and_reload_roundtrip(tmp_path):
    ignore_file = tmp_path / ".dep-audit-ignore"
    save_ignore_list(["requests", "Flask"], str(ignore_file))
    loaded = load_ignore_list(str(ignore_file))
    assert loaded == {"requests", "flask"}


# ---------------------------------------------------------------------------
# apply_ignore / is_ignored
# ---------------------------------------------------------------------------

def test_apply_ignore_removes_matching_deps():
    deps = [_dep("requests"), _dep("flask"), _dep("boto3")]
    result = apply_ignore(deps, {"requests", "boto3"})
    assert [d.name for d in result] == ["flask"]


def test_apply_ignore_returns_all_when_set_empty():
    deps = [_dep("requests"), _dep("flask")]
    assert apply_ignore(deps, set()) == deps


def test_is_ignored_true():
    assert is_ignored(_dep("Requests"), {"requests"}) is True


def test_is_ignored_false():
    assert is_ignored(_dep("flask"), {"requests"}) is False
