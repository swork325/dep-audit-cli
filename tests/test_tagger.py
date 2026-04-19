"""Tests for dep_audit.tagger."""
import json
from pathlib import Path

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.tagger import (
    load_tag_map,
    save_tag_map,
    tags_for_dep,
    tag_report,
    filter_by_tag,
)


def _dep(name: str, latest: str = "2.0.0", current: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulns=[])


def _report() -> AuditReport:
    return AuditReport(files=[
        FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask")]),
        FileAudit(path="dev.txt", deps=[_dep("pytest"), _dep("requests")]),
    ])


def test_load_returns_empty_when_missing(tmp_path):
    assert load_tag_map(tmp_path / "none.json") == {}


def test_load_returns_empty_on_invalid_json(tmp_path):
    p = tmp_path / "tags.json"
    p.write_text("not json")
    assert load_tag_map(p) == {}


def test_load_returns_empty_on_wrong_type(tmp_path):
    p = tmp_path / "tags.json"
    p.write_text(json.dumps(["a", "b"]))
    assert load_tag_map(p) == {}


def test_load_normalises_keys_to_lowercase(tmp_path):
    p = tmp_path / "tags.json"
    p.write_text(json.dumps({"Requests": ["http", "core"]}))
    result = load_tag_map(p)
    assert "requests" in result
    assert result["requests"] == ["http", "core"]


def test_save_and_reload(tmp_path):
    p = tmp_path / "tags.json"
    tag_map = {"flask": ["web"], "pytest": ["dev"]}
    save_tag_map(tag_map, p)
    loaded = load_tag_map(p)
    assert loaded["flask"] == ["web"]
    assert loaded["pytest"] == ["dev"]


def test_tags_for_dep_returns_tags():
    tag_map = {"requests": ["http", "core"]}
    dep = _dep("requests")
    assert tags_for_dep(dep, tag_map) == ["http", "core"]


def test_tags_for_dep_returns_empty_when_not_found():
    dep = _dep("flask")
    assert tags_for_dep(dep, {}) == []


def test_tag_report_groups_by_tag():
    tag_map = {"requests": ["http"], "flask": ["http", "web"], "pytest": ["dev"]}
    grouped = tag_report(_report(), tag_map)
    assert len(grouped["http"]) == 3  # requests x2 + flask
    assert len(grouped["dev"]) == 1
    assert "web" in grouped


def test_filter_by_tag_keeps_only_matching_deps():
    tag_map = {"requests": ["http"], "flask": ["web"]}
    result = filter_by_tag(_report(), "http", tag_map)
    all_names = [d.name for fa in result.files for d in fa.deps]
    assert all(n == "requests" for n in all_names)
    assert "flask" not in all_names


def test_filter_by_tag_excludes_empty_files():
    tag_map = {"requests": ["http"]}
    result = filter_by_tag(_report(), "http", tag_map)
    # dev.txt has requests; req.txt also has requests — both kept
    assert len(result.files) == 2


def test_filter_by_unknown_tag_returns_empty_report():
    result = filter_by_tag(_report(), "nonexistent", {})
    assert result.files == []
