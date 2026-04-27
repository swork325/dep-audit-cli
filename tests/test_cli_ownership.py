"""Tests for dep_audit.cli_ownership."""
from __future__ import annotations

import argparse
import json
from io import StringIO
from unittest.mock import patch

import pytest

from dep_audit.cli_ownership import (
    add_ownership_args,
    maybe_render_ownership,
)
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep


def _dep(name: str) -> ResolvedDep:
    return ResolvedDep(name=name, current_version="1.0", latest_version="1.0", vulnerabilities=[])


def _report(*dep_lists) -> AuditReport:
    files = [FileAudit(path=f"r{i}.txt", deps=list(d)) for i, d in enumerate(dep_lists)]
    return AuditReport(files=files)


def _parse(extra: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_ownership_args(parser)
    return parser.parse_args(extra or [])


def test_defaults():
    args = _parse()
    assert args.owner_map is None
    assert args.show_ownership is False
    assert args.ownership_format == "text"


def test_show_ownership_flag():
    args = _parse(["--show-ownership"])
    assert args.show_ownership is True


def test_ownership_format_json():
    args = _parse(["--ownership-format", "json"])
    assert args.ownership_format == "json"


def test_maybe_render_ownership_skipped_when_flag_false(capsys):
    args = _parse()
    report = _report([_dep("flask")])
    maybe_render_ownership(args, report)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_maybe_render_ownership_text_output(capsys, tmp_path):
    owner_file = tmp_path / "owners.json"
    owner_file.write_text(json.dumps({"flask": "team-x"}))
    args = _parse(["--show-ownership", "--owner-map", str(owner_file)])
    report = _report([_dep("flask")])
    maybe_render_ownership(args, report)
    captured = capsys.readouterr()
    assert "team-x" in captured.out
    assert "flask" in captured.out


def test_maybe_render_ownership_json_output(capsys, tmp_path):
    owner_file = tmp_path / "owners.json"
    owner_file.write_text(json.dumps({"requests": "team-y"}))
    args = _parse(
        ["--show-ownership", "--ownership-format", "json", "--owner-map", str(owner_file)]
    )
    report = _report([_dep("requests")])
    maybe_render_ownership(args, report)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "team-y" in data
    assert "requests" in data["team-y"]


def test_unassigned_shown_in_text(capsys):
    args = _parse(["--show-ownership"])
    report = _report([_dep("mystery-lib")])
    maybe_render_ownership(args, report)
    captured = capsys.readouterr()
    assert "Unassigned" in captured.out
