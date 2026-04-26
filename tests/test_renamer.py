"""Tests for dep_audit.renamer."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.renamer import (
    _rename_dep,
    load_rename_map,
    rename_report,
    save_rename_map,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, pinned: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, pinned=pinned, latest=latest, vulns=[])


# ---------------------------------------------------------------------------
# load_rename_map
# ---------------------------------------------------------------------------

def test_load_returns_builtins_when_no_file():
    rmap = load_rename_map(None)
    assert rmap["pil"] == "Pillow"
    assert rmap["sklearn"] == "scikit-learn"


def test_load_returns_builtins_when_file_missing(tmp_path: Path):
    rmap = load_rename_map(tmp_path / "nonexistent.json")
    assert "pil" in rmap


def test_load_merges_user_file(tmp_path: Path):
    p = tmp_path / "renames.json"
    p.write_text(json.dumps({"mylib": "my-library"}), encoding="utf-8")
    rmap = load_rename_map(p)
    assert rmap["mylib"] == "my-library"
    assert rmap["pil"] == "Pillow"  # built-in still present


def test_load_normalises_keys_to_lowercase(tmp_path: Path):
    p = tmp_path / "renames.json"
    p.write_text(json.dumps({"MyAlias": "canonical-pkg"}), encoding="utf-8")
    rmap = load_rename_map(p)
    assert "myalias" in rmap
    assert "MyAlias" not in rmap


def test_load_returns_builtins_on_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    rmap = load_rename_map(p)
    assert "pil" in rmap


def test_load_returns_builtins_on_wrong_type(tmp_path: Path):
    p = tmp_path / "wrong.json"
    p.write_text("["  + json.dumps(["a", "b"]) + "]", encoding="utf-8")
    rmap = load_rename_map(p)
    assert "pil" in rmap


# ---------------------------------------------------------------------------
# save_rename_map
# ---------------------------------------------------------------------------

def test_save_and_reload(tmp_path: Path):
    p = tmp_path / "renames.json"
    save_rename_map({"myalias": "MyPackage"}, p)
    rmap = load_rename_map(p)
    assert rmap["myalias"] == "MyPackage"


# ---------------------------------------------------------------------------
# _rename_dep
# ---------------------------------------------------------------------------

def test_rename_dep_applies_canonical():
    dep = _dep("pil")
    result = _rename_dep(dep, {"pil": "Pillow"})
    assert result.name == "Pillow"


def test_rename_dep_unchanged_when_no_match():
    dep = _dep("requests")
    result = _rename_dep(dep, {"pil": "Pillow"})
    assert result.name == "requests"


def test_rename_dep_unchanged_when_already_canonical():
    dep = _dep("Pillow")
    result = _rename_dep(dep, {"pillow": "Pillow"})
    assert result.name == "Pillow"


# ---------------------------------------------------------------------------
# rename_report
# ---------------------------------------------------------------------------

def test_rename_report_renames_matching_deps():
    report = AuditReport(
        files=[
            FileAudit(path="requirements.txt", deps=[_dep("pil"), _dep("requests")]),
        ]
    )
    result = rename_report(report, {"pil": "Pillow"})
    names = [d.name for d in result.files[0].deps]
    assert "Pillow" in names
    assert "pil" not in names
    assert "requests" in names


def test_rename_report_preserves_original():
    """rename_report must not mutate the original report."""
    report = AuditReport(
        files=[FileAudit(path="r.txt", deps=[_dep("pil")])]
    )
    rename_report(report, {"pil": "Pillow"})
    assert report.files[0].deps[0].name == "pil"
