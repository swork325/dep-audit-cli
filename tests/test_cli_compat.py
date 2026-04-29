"""Tests for dep_audit.cli_compat."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_compat import (
    _render_json,
    _render_text,
    add_compat_args,
    maybe_render_compat,
)
from dep_audit.auditor_compat import build_compat_report
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        is_outdated=False,
        vuln_result=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*names) -> AuditReport:
    deps = [_dep(n) for n in names]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


def _parse(args: list) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_compat_args(p)
    return p.parse_args(args)


# --- parser defaults ---

def test_defaults():
    ns = _parse([])
    assert ns.compat is False
    assert ns.compat_runtime is None
    assert ns.compat_format == "text"


def test_compat_flag_sets_true():
    ns = _parse(["--compat"])
    assert ns.compat is True


def test_custom_runtime():
    ns = _parse(["--compat", "--compat-runtime", "3.11"])
    assert ns.compat_runtime == "3.11"


def test_json_format():
    ns = _parse(["--compat", "--compat-format", "json"])
    assert ns.compat_format == "json"


# --- _render_text ---

def test_render_text_all_compatible():
    report = _report("requests")
    cr = build_compat_report(report, "3.9", {})
    out = _render_text(cr, "3.9")
    assert "All dependencies are compatible" in out
    assert "3.9" in out


def test_render_text_shows_incompatible():
    report = _report("flask")
    cr = build_compat_report(report, "3.9", {"flask": ">=3.12"})
    out = _render_text(cr, "3.9")
    assert "INCOMPATIBLE" in out
    assert "flask" in out


# --- _render_json ---

def test_render_json_structure():
    report = _report("requests")
    cr = build_compat_report(report, "3.9", {})
    raw = _render_json(cr, "3.9")
    data = json.loads(raw)
    assert data["runtime"] == "3.9"
    assert "total" in data
    assert "incompatible_count" in data
    assert isinstance(data["entries"], list)


# --- maybe_render_compat ---

def test_maybe_render_compat_skips_when_flag_false(capsys):
    ns = _parse([])
    report = _report("requests")
    maybe_render_compat(ns, report)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_maybe_render_compat_prints_when_flag_set(capsys):
    ns = _parse(["--compat", "--compat-runtime", "3.9"])
    report = _report("requests")
    maybe_render_compat(ns, report, {})
    captured = capsys.readouterr()
    assert "3.9" in captured.out


def test_maybe_render_compat_json(capsys):
    ns = _parse(["--compat", "--compat-runtime", "3.9", "--compat-format", "json"])
    report = _report("requests")
    maybe_render_compat(ns, report, {})
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["runtime"] == "3.9"
