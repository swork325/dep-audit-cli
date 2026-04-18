"""Tests for dep_audit.trend."""
import json
import time
from pathlib import Path

import pytest

from dep_audit.trend import (
    TrendEntry,
    TrendHistory,
    load_trend,
    save_trend,
    record_trend,
)
from dep_audit.reporter import SummaryStats


def _stats(total=10, outdated=3, vulnerable=1, issue_rate=0.4):
    return SummaryStats(
        total_files=2,
        clean_files=1,
        total_deps=total,
        outdated_deps=outdated,
        vulnerable_deps=vulnerable,
        issue_rate=issue_rate,
    )


def test_trend_history_add_creates_entry():
    h = TrendHistory()
    e = h.add(_stats())
    assert isinstance(e, TrendEntry)
    assert e.total_deps == 10
    assert e.outdated == 3
    assert e.vulnerable == 1
    assert len(h.entries) == 1


def test_trend_history_last_returns_most_recent():
    h = TrendHistory()
    h.add(_stats(total=5))
    h.add(_stats(total=8))
    assert h.last().total_deps == 8


def test_trend_history_last_returns_none_when_empty():
    assert TrendHistory().last() is None


def test_trend_history_since_filters_by_timestamp():
    h = TrendHistory()
    old = TrendEntry(timestamp=1000.0, total_deps=1, outdated=0, vulnerable=0, issue_rate=0.0)
    new = TrendEntry(timestamp=time.time(), total_deps=2, outdated=0, vulnerable=0, issue_rate=0.0)
    h.entries = [old, new]
    result = h.since(5000.0)
    assert len(result) == 1
    assert result[0].total_deps == 2


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "trend.json"
    h = TrendHistory()
    h.add(_stats(total=7))
    save_trend(h, path)
    loaded = load_trend(path)
    assert len(loaded.entries) == 1
    assert loaded.entries[0].total_deps == 7


def test_load_missing_file_returns_empty(tmp_path):
    h = load_trend(tmp_path / "missing.json")
    assert h.entries == []


def test_load_invalid_json_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json")
    h = load_trend(p)
    assert h.entries == []


def test_record_trend_appends_to_existing(tmp_path):
    path = tmp_path / "trend.json"
    record_trend(_stats(total=4), path)
    record_trend(_stats(total=6), path)
    h = load_trend(path)
    assert len(h.entries) == 2
    assert h.entries[1].total_deps == 6
