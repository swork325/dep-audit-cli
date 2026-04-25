"""Tests for dep_audit.cli_badge."""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_badge import add_badge_args, maybe_render_badge
from dep_audit.resolver import ResolvedDep


def _dep(name="pkg", installed="1.0.0", latest="1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, installed_version=installed, latest_version=latest, vulns=[])


def _report() -> AuditReport:
    return AuditReport(file_audits=[FileAudit(path="req.txt", deps=[_dep()])])


def _parse(extra: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_badge_args(parser)
    return parser.parse_args(extra or [])


def test_defaults():
    args = _parse()
    assert args.badge is False
    assert args.badge_label == "dependencies"
    assert args.badge_out is None


def test_badge_flag():
    args = _parse(["--badge"])
    assert args.badge is True


def test_custom_label():
    args = _parse(["--badge", "--badge-label", "my-app"])
    assert args.badge_label == "my-app"


def test_no_badge_flag_does_nothing():
    buf = io.StringIO()
    args = _parse([])
    maybe_render_badge(args, _report(), out=buf)
    assert buf.getvalue() == ""


def test_badge_writes_json_to_stdout():
    buf = io.StringIO()
    args = _parse(["--badge"])
    maybe_render_badge(args, _report(), out=buf)
    data = json.loads(buf.getvalue())
    assert "schemaVersion" in data
    assert "color" in data
    assert "message" in data


def test_badge_writes_to_file(tmp_path: Path):
    out_file = tmp_path / "badge.json"
    args = _parse(["--badge", "--badge-out", str(out_file)])
    maybe_render_badge(args, _report())
    data = json.loads(out_file.read_text())
    assert data["label"] == "dependencies"


def test_badge_custom_label_in_output():
    buf = io.StringIO()
    args = _parse(["--badge", "--badge-label", "backend"])
    maybe_render_badge(args, _report(), out=buf)
    data = json.loads(buf.getvalue())
    assert data["label"] == "backend"
