"""Tests for dep_audit.ownership."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.ownership import (
    OwnershipReport,
    OwnedDep,
    build_ownership_report,
    load_owner_map,
    owner_for_dep,
    save_owner_map,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit


def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


def _report(*pairs) -> AuditReport:
    files = [FileAudit(path=f"req{i}.txt", deps=list(deps)) for i, deps in enumerate(pairs)]
    return AuditReport(files=files)


def test_load_returns_empty_when_no_file():
    assert load_owner_map(None) == {}


def test_load_returns_empty_when_file_missing(tmp_path):
    result = load_owner_map(str(tmp_path / "missing.json"))
    assert result == {}


def test_load_returns_empty_on_invalid_json(tmp_path):
    p = tmp_path / "owners.json"
    p.write_text("not json")
    assert load_owner_map(str(p)) == {}


def test_load_returns_empty_on_wrong_type(tmp_path):
    p = tmp_path / "owners.json"
    p.write_text(json.dumps(["a", "b"]))
    assert load_owner_map(str(p)) == {}


def test_load_normalises_keys_to_lowercase(tmp_path):
    p = tmp_path / "owners.json"
    p.write_text(json.dumps({"Requests": "team-a"}))
    result = load_owner_map(str(p))
    assert result["requests"] == "team-a"


def test_save_and_reload(tmp_path):
    p = str(tmp_path / "owners.json")
    save_owner_map({"flask": "team-b"}, p)
    result = load_owner_map(p)
    assert result["flask"] == "team-b"


def test_owner_for_dep_found():
    dep = _dep("requests")
    assert owner_for_dep(dep, {"requests": "team-a"}) == "team-a"


def test_owner_for_dep_not_found():
    dep = _dep("flask")
    assert owner_for_dep(dep, {"requests": "team-a"}) is None


def test_owner_for_dep_case_insensitive():
    dep = _dep("Requests")
    assert owner_for_dep(dep, {"requests": "team-a"}) == "team-a"


def test_build_ownership_report_groups_by_owner():
    d1 = _dep("requests")
    d2 = _dep("flask")
    report = _report([d1], [d2])
    owner_map = {"requests": "team-a", "flask": "team-a"}
    ow = build_ownership_report(report, owner_map)
    by_owner = ow.by_owner()
    assert "team-a" in by_owner
    assert len(by_owner["team-a"]) == 2


def test_build_ownership_report_unassigned():
    d1 = _dep("requests")
    d2 = _dep("flask")
    report = _report([d1, d2])
    ow = build_ownership_report(report, {})
    assert len(ow.unassigned()) == 2


def test_by_owner_uses_unassigned_key_for_none():
    d1 = _dep("unknown-pkg")
    report = _report([d1])
    ow = build_ownership_report(report, {})
    assert "(unassigned)" in ow.by_owner()
