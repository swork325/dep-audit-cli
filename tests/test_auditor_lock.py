"""Tests for dep_audit.auditor_lock."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.auditor_lock import (
    LockEntry,
    LockInconsistency,
    LockReport,
    check_lock_consistency,
    parse_lock_file,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, current: str = "1.0.0", latest: str | None = None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=latest is not None and latest != current,
        vulnerabilities=[],
    )


# ---------------------------------------------------------------------------
# parse_lock_file
# ---------------------------------------------------------------------------

def test_parse_lock_file_reads_pinned_lines(tmp_path: Path):
    lock = tmp_path / "requirements.lock"
    lock.write_text("requests==2.31.0\nflask==3.0.0\n")
    result = parse_lock_file(lock)
    assert result["requests"] == "2.31.0"
    assert result["flask"] == "3.0.0"


def test_parse_lock_file_ignores_comments_and_blanks(tmp_path: Path):
    lock = tmp_path / "req.txt"
    lock.write_text("# comment\n\nrequests==2.31.0\n")
    result = parse_lock_file(lock)
    assert list(result.keys()) == ["requests"]


def test_parse_lock_file_normalises_hyphens(tmp_path: Path):
    lock = tmp_path / "req.txt"
    lock.write_text("my-package==1.2.3\n")
    result = parse_lock_file(lock)
    assert "my_package" in result


def test_parse_lock_file_returns_empty_when_missing(tmp_path: Path):
    result = parse_lock_file(tmp_path / "nonexistent.txt")
    assert result == {}


# ---------------------------------------------------------------------------
# check_lock_consistency
# ---------------------------------------------------------------------------

def test_consistent_when_all_locked_at_latest(tmp_path: Path):
    lock = tmp_path / "req.lock"
    lock.write_text("requests==2.31.0\n")
    deps = [_dep("requests", "2.28.0", latest="2.31.0")]
    report = check_lock_consistency(deps, lock)
    assert report.is_consistent
    assert report.total == 0


def test_detects_missing_package(tmp_path: Path):
    lock = tmp_path / "req.lock"
    lock.write_text("")
    deps = [_dep("flask", "3.0.0", latest="3.0.0")]
    report = check_lock_consistency(deps, lock)
    assert not report.is_consistent
    assert report.inconsistencies[0].name == "flask"
    assert report.inconsistencies[0].locked_version is None
    assert "missing" in report.inconsistencies[0].reason


def test_detects_version_mismatch(tmp_path: Path):
    lock = tmp_path / "req.lock"
    lock.write_text("requests==2.28.0\n")
    deps = [_dep("requests", "2.28.0", latest="2.31.0")]
    report = check_lock_consistency(deps, lock)
    assert not report.is_consistent
    inc = report.inconsistencies[0]
    assert inc.locked_version == "2.28.0"
    assert inc.latest_version == "2.31.0"


def test_lock_report_stores_lock_file_path(tmp_path: Path):
    lock = tmp_path / "req.lock"
    lock.write_text("")
    report = check_lock_consistency([], lock)
    assert report.lock_file == str(lock)
