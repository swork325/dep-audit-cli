"""Tests for dep_audit.auditor_env and dep_audit.cli_env."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_audit.auditor_env import (
    EnvMismatch,
    EnvAuditResult,
    parse_env_file,
    compare_with_env,
)
from dep_audit.cli_env import add_env_args, maybe_render_env, _render_text, _render_json
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest,
                       vulnerabilities=[])


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# parse_env_file
# ---------------------------------------------------------------------------

def test_parse_env_file_reads_pinned(tmp_path: Path):
    env = tmp_path / "env.txt"
    env.write_text("requests==2.28.0\nflask==2.3.1\n")
    result = parse_env_file(env)
    assert result["requests"] == "2.28.0"
    assert result["flask"] == "2.3.1"


def test_parse_env_file_normalises_hyphens(tmp_path: Path):
    env = tmp_path / "env.txt"
    env.write_text("my-package==1.0.0\n")
    result = parse_env_file(env)
    assert "my_package" in result


def test_parse_env_file_ignores_comments_and_blanks(tmp_path: Path):
    env = tmp_path / "env.txt"
    env.write_text("# comment\n\nrequests==2.28.0\n-r other.txt\n")
    result = parse_env_file(env)
    assert list(result.keys()) == ["requests"]


def test_parse_env_file_returns_empty_when_missing(tmp_path: Path):
    result = parse_env_file(tmp_path / "nonexistent.txt")
    assert result == {}


# ---------------------------------------------------------------------------
# EnvMismatch
# ---------------------------------------------------------------------------

def test_env_mismatch_conflict_when_versions_differ():
    m = EnvMismatch(name="requests", required_version="2.27.0", env_version="2.28.0")
    assert m.has_conflict is True


def test_env_mismatch_no_conflict_when_versions_equal():
    m = EnvMismatch(name="requests", required_version="2.28.0", env_version="2.28.0")
    assert m.has_conflict is False


def test_env_mismatch_conflict_when_missing_from_env():
    m = EnvMismatch(name="requests", required_version="2.28.0", env_version=None,
                    missing_from_env=True)
    assert m.has_conflict is True


# ---------------------------------------------------------------------------
# compare_with_env
# ---------------------------------------------------------------------------

def test_compare_no_conflicts_when_versions_match(tmp_path: Path):
    env_file = tmp_path / "env.txt"
    env_file.write_text("requests==2.28.0\n")
    report = _report(_dep("requests", current="2.28.0"))
    result = compare_with_env(report, env_file)
    assert result.has_conflicts is False


def test_compare_detects_version_conflict(tmp_path: Path):
    env_file = tmp_path / "env.txt"
    env_file.write_text("requests==2.27.0\n")
    report = _report(_dep("requests", current="2.28.0"))
    result = compare_with_env(report, env_file)
    assert result.has_conflicts is True
    assert result.conflicts[0].name == "requests"


def test_compare_detects_missing_from_env(tmp_path: Path):
    env_file = tmp_path / "env.txt"
    env_file.write_text("")
    report = _report(_dep("flask", current="2.3.1"))
    result = compare_with_env(report, env_file)
    assert any(m.missing_from_env for m in result.mismatches)


def test_compare_detects_extra_in_env(tmp_path: Path):
    env_file = tmp_path / "env.txt"
    env_file.write_text("extra-lib==0.1.0\n")
    report = _report(_dep("requests", current="2.28.0"))
    result = compare_with_env(report, env_file)
    extra = [m for m in result.mismatches if m.missing_from_report]
    assert any(m.name == "extra_lib" for m in extra)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse(*args):
    import argparse
    p = argparse.ArgumentParser()
    add_env_args(p)
    return p.parse_args(list(args))


def test_add_env_args_defaults():
    args = _parse()
    assert args.env_file is None
    assert args.env_format == "text"


def test_render_text_no_mismatches():
    result = EnvAuditResult()
    text = _render_text(result)
    assert "All dependencies match" in text


def test_render_json_structure():
    result = EnvAuditResult(
        mismatches=[
            EnvMismatch(name="requests", required_version="2.27.0",
                        env_version="2.28.0")
        ]
    )
    data = json.loads(_render_json(result))
    assert "env_mismatches" in data
    assert data["env_mismatches"][0]["name"] == "requests"


def test_maybe_render_env_skips_when_no_flag(tmp_path: Path):
    args = _parse()
    report = _report(_dep("requests"))
    printed: list = []
    out = maybe_render_env(args, report, print_fn=printed.append)
    assert out is None
    assert printed == []


def test_maybe_render_env_prints_when_flag_set(tmp_path: Path):
    env_file = tmp_path / "env.txt"
    env_file.write_text("requests==2.28.0\n")
    args = _parse("--env-file", str(env_file))
    report = _report(_dep("requests", current="2.28.0"))
    printed: list = []
    out = maybe_render_env(args, report, print_fn=printed.append)
    assert out is not None
    assert printed
