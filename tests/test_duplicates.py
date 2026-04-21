"""Tests for dep_audit.duplicates."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.duplicates import (
    DuplicateEntry,
    DuplicatesReport,
    find_duplicates,
    render_duplicates_text,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        vulns=[],
    )


def _report(*file_specs) -> AuditReport:
    """Build an AuditReport from (path, [dep, ...]) tuples."""
    files = [
        FileAudit(path=path, deps=list(deps))
        for path, deps in file_specs
    ]
    return AuditReport(files=files)


# ---------------------------------------------------------------------------
# DuplicateEntry
# ---------------------------------------------------------------------------

def test_has_version_conflict_true():
    entry = DuplicateEntry(package="requests", occurrences=["a", "b"], versions=["2.28.0", "2.27.0"])
    assert entry.has_version_conflict is True


def test_has_version_conflict_false_same_version():
    entry = DuplicateEntry(package="requests", occurrences=["a", "b"], versions=["2.28.0", "2.28.0"])
    assert entry.has_version_conflict is False


def test_has_version_conflict_false_no_pins():
    entry = DuplicateEntry(package="requests", occurrences=["a", "b"], versions=["", ""])
    assert entry.has_version_conflict is False


# ---------------------------------------------------------------------------
# find_duplicates
# ---------------------------------------------------------------------------

def test_no_duplicates_returns_empty_report():
    report = _report(
        ("req.txt", [_dep("requests")]),
        ("dev.txt", [_dep("pytest")]),
    )
    result = find_duplicates(report)
    assert result.total == 0
    assert result.entries == []


def test_finds_duplicate_across_two_files():
    report = _report(
        ("req.txt", [_dep("requests", "2.28.0")]),
        ("dev.txt", [_dep("requests", "2.28.0")]),
    )
    result = find_duplicates(report)
    assert result.total == 1
    assert result.entries[0].package == "requests"


def test_duplicate_entry_records_both_files():
    report = _report(
        ("req.txt", [_dep("flask", "2.0.0")]),
        ("extra.txt", [_dep("flask", "2.1.0")]),
    )
    entry = find_duplicates(report).entries[0]
    assert "req.txt" in entry.occurrences
    assert "extra.txt" in entry.occurrences


def test_version_conflict_detected():
    report = _report(
        ("req.txt", [_dep("flask", "2.0.0")]),
        ("extra.txt", [_dep("flask", "2.1.0")]),
    )
    result = find_duplicates(report)
    assert len(result.conflicts) == 1


def test_normalises_package_names():
    """requests and Requests should be treated as the same package."""
    report = _report(
        ("a.txt", [_dep("Requests", "2.28.0")]),
        ("b.txt", [_dep("requests", "2.28.0")]),
    )
    result = find_duplicates(report)
    assert result.total == 1


# ---------------------------------------------------------------------------
# render_duplicates_text
# ---------------------------------------------------------------------------

def test_render_no_duplicates():
    text = render_duplicates_text(DuplicatesReport(entries=[]))
    assert "No duplicate" in text


def test_render_shows_package_name():
    report = _report(
        ("req.txt", [_dep("requests", "2.28.0")]),
        ("dev.txt", [_dep("requests", "2.28.0")]),
    )
    text = render_duplicates_text(find_duplicates(report))
    assert "requests" in text


def test_render_flags_version_conflict():
    report = _report(
        ("req.txt", [_dep("flask", "2.0.0")]),
        ("extra.txt", [_dep("flask", "2.1.0")]),
    )
    text = render_duplicates_text(find_duplicates(report))
    assert "VERSION CONFLICT" in text
