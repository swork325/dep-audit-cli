"""Tests for dep_audit.cli_alias."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from dep_audit.aliaser import DEFAULT_ALIASES
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_alias import add_alias_args, alias_map_from_args, maybe_apply_aliases
from dep_audit.resolver import ResolvedDep


def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_alias_args(parser)
    return parser.parse_args(list(args))


def _dep(name: str) -> ResolvedDep:
    return ResolvedDep(name=name, current_version="1.0", latest_version="1.0", vulnerabilities=[])


def _report(*names: str) -> AuditReport:
    deps = [_dep(n) for n in names]
    return AuditReport(files=[FileAudit(path="requirements.txt", deps=deps)])


# ---------------------------------------------------------------------------
# add_alias_args defaults
# ---------------------------------------------------------------------------

def test_defaults():
    args = _parse()
    assert args.alias_map is None
    assert args.no_default_aliases is False


def test_alias_map_flag():
    args = _parse("--alias-map", "aliases.json")
    assert args.alias_map == "aliases.json"


def test_no_default_aliases_flag():
    args = _parse("--no-default-aliases")
    assert args.no_default_aliases is True


# ---------------------------------------------------------------------------
# alias_map_from_args
# ---------------------------------------------------------------------------

def test_alias_map_from_args_returns_none_by_default():
    args = _parse()
    assert alias_map_from_args(args) is None


def test_alias_map_from_args_loads_file(tmp_path: Path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"mylib": "my-library"}))
    args = _parse("--alias-map", str(p))
    result = alias_map_from_args(args)
    assert result is not None
    assert result["mylib"] == "my-library"


def test_alias_map_from_args_no_defaults_returns_empty_without_file():
    args = _parse("--no-default-aliases")
    result = alias_map_from_args(args)
    assert result == {}


# ---------------------------------------------------------------------------
# maybe_apply_aliases
# ---------------------------------------------------------------------------

def test_maybe_apply_aliases_skips_when_no_flags():
    args = _parse()
    report = _report("pillow")
    result = maybe_apply_aliases(report, args)
    # No remapping — dep name unchanged
    assert result.files[0].deps[0].name == "pillow"


def test_maybe_apply_aliases_remaps_with_file(tmp_path: Path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({}))
    args = _parse("--alias-map", str(p))
    report = _report("pillow")
    result = maybe_apply_aliases(report, args)
    assert result.files[0].deps[0].name == "Pillow"
