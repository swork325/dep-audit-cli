"""Tests for dep_audit.cli_size."""
from __future__ import annotations

import argparse
import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.cli_size import add_size_args, maybe_render_size, _render_text, _render_json
from dep_audit.auditor_size import SizeEntry, SizeReport
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.vulnerability import VulnResult


def _dep(name="flask", current="2.0.0", latest="3.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current=current,
        latest=latest,
        outdated=True,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report() -> AuditReport:
    return AuditReport(files=[FileAudit(path="req.txt", deps=[_dep()])])


def _parse(*args) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_size_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.show_size is False
    assert ns.size_format == "text"
    assert ns.size_large_only is False


def test_show_size_flag():
    ns = _parse("--show-size")
    assert ns.show_size is True


def test_size_format_json():
    ns = _parse("--size-format", "json")
    assert ns.size_format == "json"


def test_large_only_flag():
    ns = _parse("--size-large-only")
    assert ns.size_large_only is True


def test_maybe_render_size_skips_when_flag_false(capsys):
    ns = _parse()
    maybe_render_size(ns, _report())
    captured = capsys.readouterr()
    assert captured.out == ""


def test_render_text_shows_package(capsys):
    sr = SizeReport(entries=[SizeEntry("flask", "2.0.0", 500_000, False)])
    _render_text(sr, large_only=False)
    out = capsys.readouterr().out
    assert "flask" in out
    assert "500,000" in out


def test_render_text_large_only_filters(capsys):
    sr = SizeReport(entries=[
        SizeEntry("flask", "2.0.0", 500_000, False),
        SizeEntry("django", "4.0.0", 15_000_000, True),
    ])
    _render_text(sr, large_only=True)
    out = capsys.readouterr().out
    assert "django" in out
    assert "flask" not in out


def test_render_json_output(capsys):
    sr = SizeReport(entries=[SizeEntry("flask", "2.0.0", 1024, False)])
    _render_json(sr, large_only=False)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["name"] == "flask"


def test_maybe_render_size_calls_build(monkeypatch, capsys):
    ns = _parse("--show-size")
    sr = SizeReport(entries=[SizeEntry("flask", "2.0.0", 1024, False)])
    monkeypatch.setattr("dep_audit.cli_size.build_size_report", lambda *a, **kw: sr)
    maybe_render_size(ns, _report())
    out = capsys.readouterr().out
    assert "flask" in out
