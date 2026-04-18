"""Tests for dep_audit.pinner."""
from __future__ import annotations

from pathlib import Path

import pytest

from dep_audit.pinner import _pin_line, pin_dependencies, pin_report
from dep_audit.resolver import ResolvedDep


def _dep(name: str, current: str, latest: str | None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=latest is not None and latest != current,
    )


def test_pin_line_replaces_version():
    dep = _dep("requests", "2.28.0", "2.31.0")
    result = _pin_line("requests==2.28.0\n", dep)
    assert result == "requests==2.31.0\n"


def test_pin_line_adds_pin_when_unpinned():
    dep = _dep("flask", "2.0.0", "3.0.0")
    result = _pin_line("flask\n", dep)
    assert result == "flask==3.0.0\n"


def test_pin_line_skips_comment():
    dep = _dep("flask", "2.0.0", "3.0.0")
    line = "# flask==2.0.0\n"
    assert _pin_line(line, dep) == line


def test_pin_line_no_latest_unchanged():
    dep = _dep("unknown", "1.0", None)
    line = "unknown==1.0\n"
    assert _pin_line(line, dep) == line


def test_pin_dependencies_rewrites_file(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\nflask>=2.0\n")
    deps = [_dep("requests", "2.28.0", "2.31.0"), _dep("flask", "2.0.0", "3.0.0")]
    changes = pin_dependencies(deps, req)
    content = req.read_text()
    assert "requests==2.31.0" in content
    assert "flask==3.0.0" in content
    assert len(changes) == 2


def test_pin_dependencies_no_changes(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    deps = [_dep("requests", "2.31.0", "2.31.0")]
    changes = pin_dependencies(deps, req)
    assert changes == []


def test_pin_dependencies_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        pin_dependencies([], tmp_path / "nonexistent.txt")


def test_pin_report_summary(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("boto3==1.0.0\n")
    deps = [_dep("boto3", "1.0.0", "1.34.0")]
    summary = pin_report(deps, req)
    assert "boto3==1.34.0" in summary
    assert "1 package" in summary


def test_pin_report_no_changes(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("boto3==1.34.0\n")
    deps = [_dep("boto3", "1.34.0", "1.34.0")]
    assert pin_report(deps, req) == "No changes made."
