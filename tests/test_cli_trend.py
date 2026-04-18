"""Tests for dep_audit.cli_trend."""
import argparse
from pathlib import Path

import pytest

from dep_audit.cli_trend import add_trend_args, render_trend, DEFAULT_TREND_FILE
from dep_audit.trend import TrendHistory, TrendEntry


def _parse(args=None):
    parser = argparse.ArgumentParser()
    add_trend_args(parser)
    return parser.parse_args(args or [])


def test_defaults():
    ns = _parse()
    assert ns.trend_file == DEFAULT_TREND_FILE
    assert ns.show_trend is False
    assert ns.trend_last == 5


def test_show_trend_flag():
    ns = _parse(["--show-trend"])
    assert ns.show_trend is True


def test_custom_trend_file():
    ns = _parse(["--trend-file", "custom.json"])
    assert ns.trend_file == "custom.json"


def test_trend_last_custom():
    ns = _parse(["--trend-last", "3"])
    assert ns.trend_last == 3


def test_render_trend_empty():
    h = TrendHistory()
    out = render_trend(h)
    assert "No trend data" in out


def test_render_trend_shows_entries():
    h = TrendHistory()
    h.entries = [
        TrendEntry(timestamp=1_700_000_000.0, total_deps=10, outdated=2, vulnerable=1, issue_rate=0.3),
        TrendEntry(timestamp=1_700_086_400.0, total_deps=12, outdated=3, vulnerable=0, issue_rate=0.25),
    ]
    out = render_trend(h, last_n=5)
    assert "10" in out
    assert "12" in out
    assert "Trend history" in out


def test_render_trend_respects_last_n():
    h = TrendHistory()
    for i in range(10):
        h.entries.append(
            TrendEntry(timestamp=float(1_700_000_000 + i * 3600),
                       total_deps=i, outdated=0, vulnerable=0, issue_rate=0.0)
        )
    out = render_trend(h, last_n=3)
    lines = [l for l in out.splitlines() if l.strip() and l[0] == " " and l.strip()[0].isdigit()]
    assert len(lines) == 3
