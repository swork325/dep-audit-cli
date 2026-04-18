"""Tests for dep_audit.cli."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from pathlib import Path

import pytest

from dep_audit.cli import build_parser, run
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.resolver import ResolvedDep


@pytest.fixture()
def no_scan(tmp_path):
    """Patch finder and resolver so run() doesn't hit the filesystem or network."""
    dep = ResolvedDep(
        name="requests",
        current="2.28.0",
        latest="2.31.0",
        vulnerabilities=[],
    )
    file_audit = FileAudit(path=Path("requirements.txt"), deps=[dep])

    with patch("dep_audit.cli.find_dependency_files", return_value=[Path("requirements.txt")]) as mock_find, \
         patch("dep_audit.cli.resolve_dependencies", return_value=[dep]) as mock_resolve, \
         patch("dep_audit.cli.render", return_value="mocked output") as mock_render:
        yield {"find": mock_find, "resolve": mock_resolve, "render": mock_render, "file_audit": file_audit}


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.paths == ["."]
    assert args.fmt == "text"
    assert args.exit_code is False


def test_build_parser_custom():
    parser = build_parser()
    args = parser.parse_args(["src", "lib", "--format", "json", "--exit-code"])
    assert args.paths == ["src", "lib"]
    assert args.fmt == "json"
    assert args.exit_code is True


def test_run_returns_zero_without_exit_code_flag(no_scan, tmp_path):
    exit_code = run([str(tmp_path)])
    assert exit_code == 0


def test_run_returns_one_with_exit_code_flag_when_issues(no_scan, tmp_path):
    with patch("dep_audit.cli.AuditReport") as MockReport:
        instance = MagicMock()
        instance.has_issues = True
        MockReport.return_value = instance
        exit_code = run([str(tmp_path), "--exit-code"])
    assert exit_code == 1


def test_run_calls_render_with_correct_fmt(no_scan, tmp_path):
    run([str(tmp_path), "--format", "json"])
    no_scan["render"].assert_called_once()
    _, kwargs = no_scan["render"].call_args
    assert kwargs.get("fmt") == "json" or no_scan["render"].call_args[0][1] == "json"


def test_run_scans_multiple_paths(no_scan, tmp_path):
    run([str(tmp_path), str(tmp_path)])
    assert no_scan["find"].call_count == 2
