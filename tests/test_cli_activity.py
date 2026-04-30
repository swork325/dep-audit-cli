"""Tests for dep_audit.cli_activity."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_activity import ActivityEntry, ActivityReport
from dep_audit.cli_activity import (
    add_activity_args,
    maybe_render_activity,
    _render_text,
    _render_json,
)
from dep_audit.resolver import ResolvedDep


def _dep(name="requests") -> ResolvedDep:
    return ResolvedDep(name=name, current_version="2.0", latest_version="3.0", vulnerabilities=[])


def _parse(*args) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_activity_args(parser)
    return parser.parse_args(list(args))


def _report() -> AuditReport:
    return AuditReport(files=[FileAudit(path="r.txt", deps=[_dep()])])


def _activity() -> ActivityReport:
    e = ActivityEntry("requests", "2.0", datetime(2020, 1, 1, tzinfo=timezone.utc), 1500, True)
    return ActivityReport(entries=[e])


def test_defaults():
    ns = _parse()
    assert ns.show_activity is False
    assert ns.activity_threshold == 365
    assert ns.activity_format == "text"
    assert ns.activity_inactive_only is False


def test_show_activity_flag():
    ns = _parse("--show-activity")
    assert ns.show_activity is True


def test_activity_threshold_custom():
    ns = _parse("--activity-threshold", "180")
    assert ns.activity_threshold == 180


def test_activity_format_json():
    ns = _parse("--activity-format", "json")
    assert ns.activity_format == "json"\n

def test_activity_inactive_only_flag():
    ns = _parse("--activity-inactive-only")
    assert ns.activity_inactive_only is True


def test_render_text_shows_inactive(capsys):
    _render_text(_activity(), inactive_only=False)
    out = capsys.readouterr().out
    assert "INACTIVE" in out
    assert "requests" in out


def test_render_text_inactive_only_filters(capsys):
    active = ActivityEntry("flask", "1.0", datetime(2024, 1, 1, tzinfo=timezone.utc), 10, False)
    ar = ActivityReport(entries=[active])
    _render_text(ar, inactive_only=True)
    out = capsys.readouterr().out
    assert "flask" not in out
    assert "No entries" in out


def test_render_json_is_valid_json(capsys):
    _render_json(_activity(), inactive_only=False)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["name"] == "requests"


def test_maybe_render_activity_skips_when_flag_false(capsys):
    ns = _parse()
    maybe_render_activity(ns, _report())
    assert capsys.readouterr().out == ""


def test_maybe_render_activity_calls_build(capsys):
    ns = _parse("--show-activity")
    with patch("dep_audit.cli_activity.build_activity_report", return_value=_activity()) as m:
        maybe_render_activity(ns, _report())
    m.assert_called_once()
    out = capsys.readouterr().out
    assert "Activity Report" in out
