"""Tests for dep_audit.auditor_freshness and dep_audit.cli_freshness."""
from __future__ import annotations

import argparse
import io
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_freshness import (
    FreshnessEntry,
    FreshnessReport,
    _version_distance,
    _make_entry,
    build_freshness_report,
)
from dep_audit.cli_freshness import (
    add_freshness_args,
    _render_text,
    _render_json,
    maybe_render_freshness,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, current: str, latest: str) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=current != latest,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# _version_distance
# ---------------------------------------------------------------------------

def test_version_distance_same_version():
    assert _version_distance("1.2.3", "1.2.3") == (0, 0)


def test_version_distance_one_major_behind():
    assert _version_distance("1.9.0", "2.0.0") == (1, 0)


def test_version_distance_minor_behind():
    assert _version_distance("1.1.0", "1.4.0") == (0, 3)


def test_version_distance_latest_older_returns_zero():
    assert _version_distance("2.0.0", "1.0.0") == (0, 0)


def test_version_distance_invalid_version_returns_zero():
    assert _version_distance("not-a-version", "1.0.0") == (0, 0)


# ---------------------------------------------------------------------------
# _make_entry
# ---------------------------------------------------------------------------

def test_make_entry_marks_stale_when_major_gap():
    dep = _dep("flask", "1.0.0", "3.0.0")
    entry = _make_entry(dep, major_threshold=1, minor_threshold=3)
    assert entry.stale is True
    assert entry.major_behind == 2


def test_make_entry_not_stale_when_within_thresholds():
    dep = _dep("flask", "1.0.0", "1.1.0")
    entry = _make_entry(dep, major_threshold=1, minor_threshold=3)
    assert entry.stale is False


def test_make_entry_stale_when_minor_gap_meets_threshold():
    dep = _dep("requests", "2.1.0", "2.4.0")
    entry = _make_entry(dep, major_threshold=1, minor_threshold=3)
    assert entry.stale is True
    assert entry.minor_behind == 3


# ---------------------------------------------------------------------------
# build_freshness_report
# ---------------------------------------------------------------------------

def test_build_freshness_report_total():
    r = _report(_dep("a", "1.0", "2.0"), _dep("b", "0.5", "0.5"))
    fr = build_freshness_report(r)
    assert fr.total == 2


def test_build_freshness_report_stale_count():
    r = _report(_dep("a", "1.0", "2.0"), _dep("b", "0.5", "0.5"))
    fr = build_freshness_report(r)
    assert fr.stale_count == 1


def test_build_freshness_report_deduplicates_across_files():
    dep = _dep("requests", "2.0.0", "3.0.0")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    fr = build_freshness_report(report)
    assert fr.total == 1


# ---------------------------------------------------------------------------
# FreshnessReport helpers
# ---------------------------------------------------------------------------

def test_freshness_report_stale_entries_filters():
    entries = [
        FreshnessEntry(name="a", current="1.0", latest="2.0", major_behind=1, stale=True),
        FreshnessEntry(name="b", current="1.0", latest="1.0", stale=False),
    ]
    fr = FreshnessReport(entries=entries)
    assert len(fr.stale_entries) == 1
    assert fr.stale_entries[0].name == "a"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_render_text_contains_header():
    fr = FreshnessReport(entries=[])
    assert "Freshness Report" in _render_text(fr)


def test_render_text_shows_stale_tag():
    e = FreshnessEntry(name="django", current="2.0", latest="4.0", major_behind=2, stale=True)
    fr = FreshnessReport(entries=[e])
    text = _render_text(fr)
    assert "[STALE]" in text
    assert "django" in text


def test_render_json_structure():
    e = FreshnessEntry(name="flask", current="1.0", latest="2.0", major_behind=1, stale=True)
    fr = FreshnessReport(entries=[e])
    data = json.loads(_render_json(fr))
    assert "total" in data
    assert "stale_count" in data
    assert "entries" in data
    assert data["entries"][0]["name"] == "flask"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def _parse(*argv):
    p = argparse.ArgumentParser()
    add_freshness_args(p)
    return p.parse_args(list(argv))


def test_defaults():
    args = _parse()
    assert args.freshness is False
    assert args.freshness_format == "text"
    assert args.freshness_major == 1
    assert args.freshness_minor == 3


def test_freshness_flag():
    args = _parse("--freshness")
    assert args.freshness is True


def test_freshness_format_json():
    args = _parse("--freshness", "--freshness-format", "json")
    assert args.freshness_format == "json"


def test_maybe_render_freshness_returns_none_when_not_requested():
    args = _parse()
    r = _report(_dep("x", "1.0", "2.0"))
    result = maybe_render_freshness(args, r, out=io.StringIO())
    assert result is None


def test_maybe_render_freshness_returns_report_when_requested():
    args = _parse("--freshness")
    r = _report(_dep("x", "1.0", "2.0"))
    buf = io.StringIO()
    result = maybe_render_freshness(args, r, out=buf)
    assert result is not None
    assert result.total == 1


def test_maybe_render_freshness_json_output():
    args = _parse("--freshness", "--freshness-format", "json")
    r = _report(_dep("x", "1.0", "2.0"))
    buf = io.StringIO()
    maybe_render_freshness(args, r, out=buf)
    data = json.loads(buf.getvalue())
    assert "entries" in data
