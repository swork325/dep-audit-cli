"""Tests for dep_audit.cli_timeline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.cli_timeline import (
    add_timeline_args,
    maybe_record_and_show_timeline,
    _render_text,
    _render_json,
)
from dep_audit.timeline import Timeline, TimelineEntry


def _parse(*args):
    parser = argparse.ArgumentParser()
    add_timeline_args(parser)
    return parser.parse_args(list(args))


def _dep(name: str, version: str = "1.0.0", latest: str | None = None):
    return ResolvedDep(name=name, version=version, latest=latest, vulns=[])


def _report(*deps):
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def _timeline():
    return Timeline(
        entries={
            "requests": TimelineEntry(
                package="requests",
                first_seen="2024-01-01T00:00:00Z",
                last_seen="2024-06-01T00:00:00Z",
                seen_count=4,
                was_outdated=True,
                was_vulnerable=False,
            ),
            "flask": TimelineEntry(
                package="flask",
                first_seen="2024-03-01T00:00:00Z",
                last_seen="2024-03-01T00:00:00Z",
                seen_count=1,
                was_outdated=False,
                was_vulnerable=False,
            ),
        }
    )


def test_defaults():
    args = _parse()
    assert args.timeline is False
    assert args.timeline_format == "text"
    assert args.timeline_only_flagged is False


def test_timeline_flag():
    args = _parse("--timeline")
    assert args.timeline is True


def test_timeline_format_json():
    args = _parse("--timeline-format", "json")
    assert args.timeline_format == "json"


def test_timeline_only_flagged_flag():
    args = _parse("--timeline-only-flagged")
    assert args.timeline_only_flagged is True


def test_render_text_contains_header():
    tl = _timeline()
    out = _render_text(tl, only_flagged=False)
    assert "Package" in out
    assert "First Seen" in out


def test_render_text_shows_all_entries():
    tl = _timeline()
    out = _render_text(tl, only_flagged=False)
    assert "requests" in out
    assert "flask" in out


def test_render_text_only_flagged_hides_clean():
    tl = _timeline()
    out = _render_text(tl, only_flagged=True)
    assert "requests" in out
    assert "flask" not in out


def test_render_json_returns_list():
    tl = _timeline()
    out = _render_json(tl, only_flagged=False)
    data = json.loads(out)
    assert isinstance(data, list)
    assert len(data) == 2


def test_render_json_only_flagged():
    tl = _timeline()
    out = _render_json(tl, only_flagged=True)
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["package"] == "requests"


def test_maybe_record_and_show_timeline_writes_file(tmp_path, capsys):
    p = tmp_path / "tl.json"
    args = _parse("--timeline-file", str(p))
    report = _report(_dep("flask", "3.0.0"))
    maybe_record_and_show_timeline(args, report)
    assert p.exists()
    captured = capsys.readouterr()
    assert captured.out == ""


def test_maybe_record_and_show_timeline_prints_when_flag_set(tmp_path, capsys):
    p = tmp_path / "tl.json"
    args = _parse("--timeline", "--timeline-file", str(p))
    report = _report(_dep("flask", "3.0.0"))
    maybe_record_and_show_timeline(args, report)
    captured = capsys.readouterr()
    assert "flask" in captured.out
