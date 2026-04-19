"""Tests for dep_audit.labeler."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.labeler import (
    filter_by_label,
    label_report,
    labels_for_dep,
    load_label_map,
    save_label_map,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


@pytest.fixture
def report() -> AuditReport:
    return AuditReport(
        files=[
            FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask")]),
            FileAudit(path="dev.txt", deps=[_dep("pytest"), _dep("requests")]),
        ]
    )


def test_load_returns_empty_when_missing(tmp_path):
    assert load_label_map(tmp_path / "nope.json") == {}


def test_load_returns_empty_on_invalid_json(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text("not json")
    assert load_label_map(p) == {}


def test_load_returns_empty_on_wrong_type(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(["a", "b"]))
    assert load_label_map(p) == {}


def test_save_and_reload(tmp_path):
    p = tmp_path / "labels.json"
    data = {"web": ["requests", "flask"], "test": ["pytest"]}
    save_label_map(data, p)
    loaded = load_label_map(p)
    assert loaded == data


def test_labels_for_dep_match():
    dep = _dep("requests")
    label_map = {"web": ["requests", "flask"], "test": ["pytest"]}
    assert labels_for_dep(dep, label_map) == ["web"]


def test_labels_for_dep_no_match():
    dep = _dep("boto3")
    label_map = {"web": ["requests"]}
    assert labels_for_dep(dep, label_map) == []


def test_labels_for_dep_case_insensitive():
    dep = _dep("Requests")
    label_map = {"web": ["requests"]}
    assert "web" in labels_for_dep(dep, label_map)


def test_label_report_groups_correctly(report):
    label_map = {"web": ["requests", "flask"], "test": ["pytest"]}
    grouped = label_report(report, label_map)
    assert "web" in grouped
    assert "test" in grouped
    web_names = [d.name for d in grouped["web"]]
    assert web_names.count("requests") == 2  # appears in two files
    assert "flask" in web_names


def test_filter_by_label_returns_matching_deps(report):
    label_map = {"test": ["pytest"]}
    deps = filter_by_label(report, "test", label_map)
    assert len(deps) == 1
    assert deps[0].name == "pytest"


def test_filter_by_label_missing_label_returns_empty(report):
    label_map = {"web": ["requests"]}
    assert filter_by_label(report, "nonexistent", label_map) == []
