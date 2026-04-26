"""Tests for dep_audit.timeline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.timeline import (
    Timeline,
    TimelineEntry,
    load_timeline,
    save_timeline,
    update_timeline,
)


def _dep(name: str, version: str = "1.0.0", latest: str | None = None, vulns=None):
    return ResolvedDep(
        name=name,
        version=version,
        latest=latest,
        vulns=vulns or [],
    )


def _report(*deps):
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def test_load_returns_empty_when_missing(tmp_path):
    tl = load_timeline(tmp_path / "nope.json")
    assert tl.total() == 0


def test_load_returns_empty_on_invalid_json(tmp_path):
    p = tmp_path / "tl.json"
    p.write_text("not json")
    tl = load_timeline(p)
    assert tl.total() == 0


def test_load_returns_empty_on_wrong_type(tmp_path):
    p = tmp_path / "tl.json"
    p.write_text(json.dumps([1, 2, 3]))
    tl = load_timeline(p)
    assert tl.total() == 0


def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "tl.json"
    tl = Timeline(
        entries={
            "requests": TimelineEntry(
                package="requests",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-06-01T00:00:00Z",
                seen_count=3,
                was_outdated=True,
                was_vulnerable=False,
            )
        }
    )
    save_timeline(tl, p)
    loaded = load_timeline(p)
    assert loaded.total() == 1
    e = loaded.entries["requests"]
    assert e.seen_count == 3
    assert e.was_outdated is True


def test_update_timeline_creates_new_entry(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("flask", "2.0.0"))
    tl = update_timeline(report, p)
    assert "flask" in tl.entries
    assert tl.entries["flask"].seen_count == 1


def test_update_timeline_increments_seen_count(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("flask", "2.0.0"))
    update_timeline(report, p)
    update_timeline(report, p)
    tl = load_timeline(p)
    assert tl.entries["flask"].seen_count == 2


def test_update_timeline_marks_outdated(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("flask", "2.0.0", latest="3.0.0"))
    tl = update_timeline(report, p)
    assert tl.entries["flask"].was_outdated is True


def test_ever_vulnerable_filters_correctly(tmp_path):
    from dep_audit.vulnerability import Vulnerability

    vuln = Vulnerability(id="CVE-2024-1", description="test", severity="high", fixed_in="2.1.0")
    p = tmp_path / "tl.json"
    report = _report(_dep("requests", "2.0.0", vulns=[vuln]), _dep("flask", "3.0.0"))
    tl = update_timeline(report, p)
    flagged = tl.ever_vulnerable()
    assert len(flagged) == 1
    assert flagged[0].package == "requests"


def test_ever_outdated_filters_correctly(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("flask", "2.0.0", latest="3.0.0"), _dep("click", "8.0.0"))
    tl = update_timeline(report, p)
    flagged = tl.ever_outdated()
    assert len(flagged) == 1
    assert flagged[0].package == "flask"
