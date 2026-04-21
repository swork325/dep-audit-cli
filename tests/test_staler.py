"""Tests for dep_audit.staler and dep_audit.cli_staler."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.staler import (
    StaleDep,
    StalenessReport,
    _days_since,
    build_staleness_report,
    classify_dep,
)
from dep_audit.cli_staler import add_staler_args, render_staleness, maybe_render_staleness


def _dep(name="requests", current="2.0.0", latest="2.1.0"):
    return ResolvedDep(name=name, current=current, latest=latest)


def _old_date(days=400):
    return datetime.now(tz=timezone.utc) - timedelta(days=days)


def _recent_date(days=10):
    return datetime.now(tz=timezone.utc) - timedelta(days=days)


# --- StaleDep ---

def test_stale_dep_is_stale_when_over_threshold():
    sd = StaleDep(dep=_dep(), days_since_release=400, threshold_days=365)
    assert sd.is_stale is True


def test_stale_dep_is_fresh_when_under_threshold():
    sd = StaleDep(dep=_dep(), days_since_release=100, threshold_days=365)
    assert sd.is_stale is False


# --- _days_since ---

def test_days_since_naive_datetime():
    naive = datetime.utcnow() - timedelta(days=50)
    result = _days_since(naive)
    assert 49 <= result <= 51


def test_days_since_aware_datetime():
    aware = datetime.now(tz=timezone.utc) - timedelta(days=30)
    result = _days_since(aware)
    assert 29 <= result <= 31


# --- classify_dep ---

def test_classify_dep_returns_none_when_no_date():
    result = classify_dep(_dep(), None, 365)
    assert result is None


def test_classify_dep_stale():
    result = classify_dep(_dep(), _old_date(400), 365)
    assert result is not None
    assert result.is_stale is True


def test_classify_dep_fresh():
    result = classify_dep(_dep(), _recent_date(10), 365)
    assert result is not None
    assert result.is_stale is False


# --- build_staleness_report ---

def test_build_staleness_report_counts():
    deps = [_dep("requests"), _dep("flask"), _dep("click")]
    dates = {
        "requests": _old_date(400),
        "flask": _recent_date(5),
        "click": None,
    }
    sr = build_staleness_report(deps, dates, threshold_days=365)
    assert sr.stale_count == 1
    assert len(sr.fresh) == 1
    assert sr.total == 2


def test_build_staleness_report_stale_rate():
    deps = [_dep("a"), _dep("b")]
    dates = {"a": _old_date(400), "b": _old_date(400)}
    sr = build_staleness_report(deps, dates, threshold_days=365)
    assert sr.stale_rate == pytest.approx(1.0)


def test_build_staleness_report_empty():
    sr = build_staleness_report([], {}, threshold_days=365)
    assert sr.total == 0
    assert sr.stale_rate == 0.0


# --- CLI ---

def _parse(*args):
    p = argparse.ArgumentParser()
    add_staler_args(p)
    return p.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.show_stale is False
    assert ns.stale_days == 365


def test_show_stale_flag():
    ns = _parse("--show-stale")
    assert ns.show_stale is True


def test_custom_stale_days():
    ns = _parse("--stale-days", "180")
    assert ns.stale_days == 180


def test_render_staleness_contains_package_name():
    dep = _dep("requests")
    sd = StaleDep(dep=dep, days_since_release=400, threshold_days=365)
    sr = StalenessReport(stale=[sd], fresh=[])
    text = render_staleness(sr)
    assert "requests" in text
    assert "400" in text


def test_maybe_render_staleness_skips_when_flag_off(capsys):
    ns = _parse()  # show_stale=False
    report = MagicMock()
    result = maybe_render_staleness(ns, report)
    assert result is None
    captured = capsys.readouterr()
    assert captured.out == ""
