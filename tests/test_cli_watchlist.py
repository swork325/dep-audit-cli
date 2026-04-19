"""Tests for dep_audit.cli_watchlist."""
import argparse
import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.cli_watchlist import (
    add_watchlist_args,
    maybe_filter_by_watchlist,
    print_watchlist_summary,
)


def _dep(name: str) -> ResolvedDep:
    return ResolvedDep(name=name, installed="1.0.0", latest="2.0.0", vulns=[])


def _parse(args=None):
    parser = argparse.ArgumentParser()
    add_watchlist_args(parser)
    return parser.parse_args(args or [])


def _report():
    fa = FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask")])
    return AuditReport(files=[fa])


def test_defaults():
    args = _parse()
    assert args.watchlist is None
    assert args.show_watched_only is False


def test_show_watched_only_flag():
    args = _parse(["--show-watched-only"])
    assert args.show_watched_only is True


def test_custom_watchlist_path():
    args = _parse(["--watchlist", "custom.json"])
    assert args.watchlist == "custom.json"


def test_maybe_filter_no_flag_returns_original():
    args = _parse()
    report = _report()
    result = maybe_filter_by_watchlist(report, args)
    assert result is report


def test_maybe_filter_with_flag_and_file(tmp_path):
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps(["requests"]))
    args = _parse(["--show-watched-only", "--watchlist", str(wl)])
    report = _report()
    result = maybe_filter_by_watchlist(report, args)
    names = [d.name for fa in result.files for d in fa.deps]
    assert "requests" in names
    assert "flask" not in names


def test_maybe_filter_empty_watchlist_returns_original(tmp_path):
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps([]))
    args = _parse(["--show-watched-only", "--watchlist", str(wl)])
    report = _report()
    result = maybe_filter_by_watchlist(report, args)
    assert result is report


def test_print_watchlist_summary_no_matches(capsys):
    report = _report()
    print_watchlist_summary(report, ["boto3"])
    out = capsys.readouterr().out
    assert "No watched" in out


def test_print_watchlist_summary_shows_watched(capsys):
    report = _report()
    print_watchlist_summary(report, ["requests"])
    out = capsys.readouterr().out
    assert "requests" in out
