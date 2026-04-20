"""Tests for dep_audit.cli_pinboard."""
from __future__ import annotations

import argparse
import io

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_pinboard import (
    add_pinboard_args,
    maybe_render_pinboard,
    _render_text,
    _render_json,
)
from dep_audit.pinboard import build_pinboard
from dep_audit.resolver import ResolvedDep


def _dep(name, current="==1.0.0", latest="1.0.0", outdated=False):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=outdated,
        vulnerabilities=[],
    )


def _report(*deps):
    return AuditReport(files=[FileAudit(path="req.txt", deps=list(deps))])


def _parse(*args):
    parser = argparse.ArgumentParser()
    add_pinboard_args(parser)
    return parser.parse_args(list(args))


# --- argument defaults ---

def test_defaults():
    args = _parse()
    assert args.pinboard is False
    assert args.pinboard_format == "text"
    assert args.pinboard_unpinned_only is False


def test_pinboard_flag():
    args = _parse("--pinboard")
    assert args.pinboard is True


def test_pinboard_format_json():
    args = _parse("--pinboard-format", "json")
    assert args.pinboard_format == "json"


def test_pinboard_unpinned_only_flag():
    args = _parse("--pinboard-unpinned-only")
    assert args.pinboard_unpinned_only is True


# --- _render_text ---

def test_render_text_contains_pin_rate():
    report = _report(_dep("requests", current="==2.28.0"))
    pb = build_pinboard(report)
    text = _render_text(pb, unpinned_only=False)
    assert "pin_rate" in text or "%" in text


def test_render_text_unpinned_only_hides_pinned_section():
    report = _report(_dep("requests", current="==2.28.0"), _dep("flask", current=">=2.0"))
    pb = build_pinboard(report)
    text = _render_text(pb, unpinned_only=True)
    assert "flask" in text
    # pinned section header should not appear
    assert "Pinned (" not in text


# --- _render_json ---

def test_render_json_is_valid():
    import json
    report = _report(_dep("requests", current="==2.28.0"))
    pb = build_pinboard(report)
    data = json.loads(_render_json(pb, unpinned_only=False))
    assert "pin_rate" in data
    assert "deps" in data


# --- maybe_render_pinboard ---

def test_maybe_render_pinboard_skips_when_flag_off():
    args = _parse()
    report = _report(_dep("requests"))
    out = io.StringIO()
    result = maybe_render_pinboard(args, report, out=out)
    assert result is None
    assert out.getvalue() == ""


def test_maybe_render_pinboard_renders_when_flag_on():
    args = _parse("--pinboard")
    report = _report(_dep("flask", current=">=2.0", latest="3.0.0"))
    out = io.StringIO()
    result = maybe_render_pinboard(args, report, out=out)
    assert result is not None
    assert "flask" in out.getvalue()
