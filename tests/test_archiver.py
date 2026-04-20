"""Tests for dep_audit.archiver."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.archiver import append_to_archive, load_archive, prune_archive
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


def _dep(name="requests", current="2.0.0", latest="3.0.0", outdated=True):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        outdated=outdated,
        vulnerabilities=[],
    )


@pytest.fixture()
def report():
    fa = FileAudit(path="requirements.txt", deps=[_dep()])
    return AuditReport(files=[fa])


@pytest.fixture()
def archive_file(tmp_path):
    return str(tmp_path / "archive.jsonl")


def test_append_creates_file(report, archive_file):
    append_to_archive(report, archive_file)
    assert Path(archive_file).exists()


def test_append_writes_valid_json(report, archive_file):
    append_to_archive(report, archive_file)
    entries = load_archive(archive_file)
    assert len(entries) == 1


def test_entry_has_timestamp(report, archive_file):
    append_to_archive(report, archive_file)
    entry = load_archive(archive_file)[0]
    assert "timestamp" in entry


def test_entry_stats(report, archive_file):
    append_to_archive(report, archive_file)
    entry = load_archive(archive_file)[0]
    assert entry["total_files"] == 1
    assert entry["total_deps"] == 1
    assert entry["outdated"] == 1


def test_multiple_appends(report, archive_file):
    append_to_archive(report, archive_file)
    append_to_archive(report, archive_file)
    entries = load_archive(archive_file)
    assert len(entries) == 2


def test_load_returns_empty_when_missing(tmp_path):
    result = load_archive(str(tmp_path / "no_such_file.jsonl"))
    assert result == []


def test_load_skips_invalid_lines(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"timestamp": "t"}\nnot-json\n{"timestamp": "t2"}\n')
    entries = load_archive(str(p))
    assert len(entries) == 2


def test_prune_keeps_most_recent(report, archive_file):
    for _ in range(5):
        append_to_archive(report, archive_file)
    removed = prune_archive(archive_file, keep=3)
    assert removed == 2
    assert len(load_archive(archive_file)) == 3


def test_prune_no_op_when_within_limit(report, archive_file):
    append_to_archive(report, archive_file)
    removed = prune_archive(archive_file, keep=10)
    assert removed == 0
