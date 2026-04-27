"""Tests for dep_audit.scorer_trend and dep_audit.cli_scorer_trend."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.scorer import ScoredDep, ScoredReport
from dep_audit.scorer_trend import (
    RisingPackage,
    ScoreTrendReport,
    compare_scores,
    scores_to_dict,
)
from dep_audit.cli_scorer_trend import (
    _DEFAULT_SNAPSHOT,
    add_scorer_trend_args,
    maybe_render_score_trend,
)


def _make_scored_dep(name: str, score: float) -> ScoredDep:
    dep = MagicMock()
    dep.name = name
    sd = MagicMock(spec=ScoredDep)
    sd.dep = dep
    sd.score = score
    return sd


def _make_report(*pairs) -> ScoredReport:
    """pairs: (name, score)"""
    report = MagicMock(spec=ScoredReport)
    report.deps = [_make_scored_dep(n, s) for n, s in pairs]
    return report


# ---------------------------------------------------------------------------
# compare_scores
# ---------------------------------------------------------------------------

def test_compare_scores_identifies_rising():
    report = _make_report(("requests", 50.0), ("flask", 10.0))
    previous = {"requests": 30.0, "flask": 10.0}
    result = compare_scores(report, previous)
    assert len(result.rising) == 1
    assert result.rising[0].package == "requests"


def test_compare_scores_identifies_improving():
    report = _make_report(("django", 5.0))
    previous = {"django": 20.0}
    result = compare_scores(report, previous)
    assert "django" in result.improving


def test_compare_scores_stable_when_equal():
    report = _make_report(("numpy", 15.0))
    previous = {"numpy": 15.0}
    result = compare_scores(report, previous)
    assert "numpy" in result.stable


def test_compare_scores_new_package_goes_to_stable():
    report = _make_report(("newpkg", 25.0))
    result = compare_scores(report, {})
    assert "newpkg" in result.stable


def test_rising_package_delta():
    r = RisingPackage(package="foo", previous_score=10.0, current_score=35.0)
    assert r.delta == 25.0


def test_top_rising_limits_results():
    rising = [RisingPackage(f"pkg{i}", float(i), float(i + 10)) for i in range(10)]
    report = ScoreTrendReport(rising=rising)
    assert len(report.top_rising(3)) == 3


def test_top_rising_sorted_by_delta_descending():
    r1 = RisingPackage("a", 0.0, 5.0)
    r2 = RisingPackage("b", 0.0, 50.0)
    report = ScoreTrendReport(rising=[r1, r2])
    top = report.top_rising(2)
    assert top[0].package == "b"


def test_scores_to_dict():
    report = _make_report(("requests", 42.0), ("flask", 7.0))
    d = scores_to_dict(report)
    assert d == {"requests": 42.0, "flask": 7.0}


# ---------------------------------------------------------------------------
# add_scorer_trend_args
# ---------------------------------------------------------------------------

def _parse(args):
    parser = argparse.ArgumentParser()
    add_scorer_trend_args(parser)
    return parser.parse_args(args)


def test_defaults():
    ns = _parse([])
    assert ns.score_trend is False
    assert ns.score_snapshot == _DEFAULT_SNAPSHOT
    assert ns.score_trend_top == 5


def test_score_trend_flag():
    ns = _parse(["--score-trend"])
    assert ns.score_trend is True


def test_custom_snapshot_path():
    ns = _parse(["--score-snapshot", "/tmp/snap.json"])
    assert ns.score_snapshot == "/tmp/snap.json"


def test_custom_top_n():
    ns = _parse(["--score-trend-top", "10"])
    assert ns.score_trend_top == 10


# ---------------------------------------------------------------------------
# maybe_render_score_trend
# ---------------------------------------------------------------------------

def test_maybe_render_score_trend_skips_when_flag_false(capsys):
    ns = _parse([])
    maybe_render_score_trend(ns, _make_report(("x", 1.0)))
    assert capsys.readouterr().out == ""


def test_maybe_render_score_trend_skips_when_no_report(capsys):
    ns = _parse(["--score-trend"])
    maybe_render_score_trend(ns, None)
    assert capsys.readouterr().out == ""


def test_maybe_render_score_trend_writes_snapshot(tmp_path):
    snap = str(tmp_path / "snap.json")
    ns = _parse(["--score-trend", "--score-snapshot", snap])
    maybe_render_score_trend(ns, _make_report(("requests", 30.0)))
    data = json.loads(Path(snap).read_text())
    assert data["requests"] == 30.0


def test_maybe_render_score_trend_prints_rising(tmp_path, capsys):
    snap = str(tmp_path / "snap.json")
    Path(snap).write_text(json.dumps({"requests": 10.0}))
    ns = _parse(["--score-trend", "--score-snapshot", snap])
    maybe_render_score_trend(ns, _make_report(("requests", 40.0)))
    out = capsys.readouterr().out
    assert "requests" in out
    assert "Rising" in out
