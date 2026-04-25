"""Tests for dep_audit.cli_lock."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from dep_audit.cli_lock import (
    _render_json,
    _render_text,
    add_lock_args,
    maybe_render_lock,
)
from dep_audit.auditor_lock import LockInconsistency, LockReport
from dep_audit.resolver import ResolvedDep


def _parse(args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_lock_args(p)
    return p.parse_args(args)


def _dep(name: str, current: str = "1.0.0", latest: str | None = None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=latest is not None and latest != current,
        vulnerabilities=[],
    )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def test_defaults():
    ns = _parse([])
    assert ns.lock_file is None
    assert ns.lock_format == "text"


def test_lock_file_flag():
    ns = _parse(["--lock-file", "req.lock"])
    assert ns.lock_file == "req.lock"


def test_lock_format_json():
    ns = _parse(["--lock-format", "json"])
    assert ns.lock_format == "json"


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_consistent():
    report = LockReport(lock_file="req.lock", inconsistencies=[])
    out = _render_text(report)
    assert "consistent" in out.lower() or "✔" in out


def test_render_text_shows_inconsistency():
    inc = LockInconsistency("requests", "2.28.0", "2.31.0", "lock has 2.28.0, latest is 2.31.0")
    report = LockReport(lock_file="req.lock", inconsistencies=[inc])
    out = _render_text(report)
    assert "requests" in out
    assert "2.28.0" in out


# ---------------------------------------------------------------------------
# _render_json
# ---------------------------------------------------------------------------

def test_render_json_structure():
    report = LockReport(lock_file="req.lock", inconsistencies=[])
    data = json.loads(_render_json(report))
    assert data["is_consistent"] is True
    assert data["total_inconsistencies"] == 0
    assert isinstance(data["inconsistencies"], list)


# ---------------------------------------------------------------------------
# maybe_render_lock
# ---------------------------------------------------------------------------

def test_maybe_render_lock_no_op_when_no_flag():
    ns = _parse([])
    calls = []
    maybe_render_lock(ns, [], print_fn=calls.append)
    assert calls == []


def test_maybe_render_lock_prints_when_flag_set(tmp_path: Path):
    lock = tmp_path / "req.lock"
    lock.write_text("requests==2.31.0\n")
    ns = _parse(["--lock-file", str(lock)])
    deps = [_dep("requests", "2.28.0", latest="2.31.0")]
    calls = []
    maybe_render_lock(ns, deps, print_fn=calls.append)
    assert len(calls) == 1
    assert "req.lock" in calls[0] or str(lock) in calls[0]
