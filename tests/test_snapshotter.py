"""Tests for dep_audit.snapshotter."""
import json
import os

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.snapshotter import save_snapshot, load_snapshot, snapshot_diff


def _vuln(vid="CVE-2024-1"):
    return Vulnerability(id=vid, description="test", severity="high", fix_version="9.9")


def _dep(name="requests", current="2.0.0", latest="3.0.0", outdated=True, vulns=None):
    return ResolvedDep(name=name, current_version=current, latest_version=latest,
                       outdated=outdated, vulns=vulns or [])


@pytest.fixture()
def report():
    fa = FileAudit(path="requirements.txt", deps=[_dep(), _dep("flask", "1.0", "1.0", False)])
    return AuditReport(files=[fa])


def test_save_snapshot_creates_file(tmp_path, report):
    out = str(tmp_path / "snap.json")
    save_snapshot(report, out)
    assert os.path.exists(out)


def test_save_snapshot_has_timestamp(tmp_path, report):
    out = str(tmp_path / "snap.json")
    save_snapshot(report, out)
    data = json.loads(open(out).read())
    assert "timestamp" in data
    assert "T" in data["timestamp"]


def test_save_snapshot_stats_keys(tmp_path, report):
    out = str(tmp_path / "snap.json")
    save_snapshot(report, out)
    stats = json.loads(open(out).read())["stats"]
    for key in ("total_files", "total_deps", "outdated", "vulnerable", "issue_rate"):
        assert key in stats


def test_save_snapshot_files_structure(tmp_path, report):
    out = str(tmp_path / "snap.json")
    save_snapshot(report, out)
    files = json.loads(open(out).read())["files"]
    assert len(files) == 1
    assert files[0]["path"] == "requirements.txt"
    assert len(files[0]["deps"]) == 2


def test_load_snapshot_returns_none_when_missing(tmp_path):
    assert load_snapshot(str(tmp_path / "nope.json")) is None


def test_load_snapshot_returns_none_on_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json")
    assert load_snapshot(str(p)) is None


def test_load_snapshot_round_trips(tmp_path, report):
    out = str(tmp_path / "snap.json")
    save_snapshot(report, out)
    data = load_snapshot(out)
    assert data is not None
    assert data["stats"]["total_deps"] == 2


def test_snapshot_diff_added_removed():
    old = {"stats": {"outdated": 1, "vulnerable": 0},
           "files": [{"path": "req.txt", "deps": [{"name": "flask"}]}]}
    new = {"stats": {"outdated": 2, "vulnerable": 1},
           "files": [{"path": "req.txt", "deps": [{"name": "requests"}]}]}
    diff = snapshot_diff(old, new)
    assert ("req.txt", "requests") in [tuple(x) for x in diff["added"]]
    assert ("req.txt", "flask") in [tuple(x) for x in diff["removed"]]
    assert diff["outdated_delta"] == 1
    assert diff["vulnerable_delta"] == 1


def test_snapshot_diff_no_changes():
    snap = {"stats": {"outdated": 0, "vulnerable": 0},
            "files": [{"path": "r.txt", "deps": [{"name": "six"}]}]}
    diff = snapshot_diff(snap, snap)
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["outdated_delta"] == 0
