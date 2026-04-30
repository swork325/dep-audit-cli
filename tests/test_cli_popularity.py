"""Tests for dep_audit.cli_popularity."""
from __future__ import annotations

import argparse
import io
import json

import pytest

from dep_audit.cli_popularity import (
    add_popularity_args,
    maybe_render_popularity,
    _render_text,
    _render_json,
)
from dep_audit.auditor_popularity import PopularityEntry, PopularityReport
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit


def _dep(name: str = "requests", version: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(name=name, version=version, latest=version, vulns=[])


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_popularity_args(parser)
    return parser.parse_args(list(args))


# --- add_popularity_args defaults ---

def test_defaults():
    ns = _parse()
    assert ns.popularity is False
    assert ns.popularity_format == "text"
    assert ns.popularity_top == 0


def test_popularity_flag_sets_true():
    ns = _parse("--popularity")
    assert ns.popularity is True


def test_popularity_format_json():
    ns = _parse("--popularity-format", "json")
    assert ns.popularity_format == "json"


def test_popularity_top_custom():
    ns = _parse("--popularity-top", "10")
    assert ns.popularity_top == 10


# --- _render_text ---

def test_render_text_contains_header():
    pop = PopularityReport(entries=[
        PopularityEntry("requests", "2.28.0", 1_000_000, 250_000, 35_000)
    ])
    out = _render_text(pop, top=0)
    assert "Popularity Report" in out
    assert "requests" in out


def test_render_text_no_entries_shows_message():
    pop = PopularityReport(entries=[])
    out = _render_text(pop, top=0)
    assert "No popularity data" in out


def test_render_text_none_values_show_na():
    pop = PopularityReport(entries=[
        PopularityEntry("flask", "3.0.0", None, None, None)
    ])
    out = _render_text(pop, top=0)
    assert "n/a" in out


# --- _render_json ---

def test_render_json_is_valid_json():
    pop = PopularityReport(entries=[
        PopularityEntry("requests", "2.28.0", 100, 20, 3)
    ])
    raw = _render_json(pop, top=0)
    data = json.loads(raw)
    assert isinstance(data, list)
    assert data[0]["name"] == "requests"


def test_render_json_top_limits_entries():
    entries = [
        PopularityEntry("a", "1.0", 900, 10, 1),
        PopularityEntry("b", "1.0", 100, 10, 1),
        PopularityEntry("c", "1.0", 500, 10, 1),
    ]
    pop = PopularityReport(entries=entries)
    raw = _render_json(pop, top=2)
    data = json.loads(raw)
    assert len(data) == 2


# --- maybe_render_popularity ---

def test_maybe_render_popularity_skips_when_flag_false():
    ns = _parse()
    report = _report(_dep())
    out = io.StringIO()
    result = maybe_render_popularity(ns, report, out=out)
    assert result is None
    assert out.getvalue() == ""


def test_maybe_render_popularity_returns_report_when_enabled(monkeypatch):
    from dep_audit import auditor_popularity
    entry = PopularityEntry("requests", "2.28.0", 100, 20, 3)
    monkeypatch.setattr(auditor_popularity, "build_popularity_report",
                        lambda r, session=None: PopularityReport(entries=[entry]))
    ns = _parse("--popularity")
    report = _report(_dep())
    out = io.StringIO()
    result = maybe_render_popularity(ns, report, out=out)
    assert result is not None
    assert result.total == 1
    assert "Popularity Report" in out.getvalue()
