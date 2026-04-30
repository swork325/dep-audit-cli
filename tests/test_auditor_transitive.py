"""Tests for dep_audit.auditor_transitive and dep_audit.cli_transitive."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_transitive import (
    TransitiveReport,
    TransitiveEntry,
    build_transitive_report,
)
from dep_audit.cli_transitive import (
    add_transitive_args,
    maybe_render_transitive,
    _render_text,
    _render_json,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        is_outdated=False,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*names: str) -> AuditReport:
    deps = [_dep(n) for n in names]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# TransitiveReport helpers
# ---------------------------------------------------------------------------

def test_total_counts_all_entries():
    tr = TransitiveReport(entries=[
        TransitiveEntry("requests", "2.31.0", [], True),
        TransitiveEntry("urllib3", "1.26.0", ["requests"], False),
    ])
    assert tr.total == 2


def test_indirect_count():
    tr = TransitiveReport(entries=[
        TransitiveEntry("requests", "2.31.0", [], True),
        TransitiveEntry("urllib3", "1.26.0", ["requests"], False),
    ])
    assert tr.indirect_count == 1
    assert tr.direct_count == 1


def test_indirect_only_filters():
    tr = TransitiveReport(entries=[
        TransitiveEntry("requests", "2.31.0", [], True),
        TransitiveEntry("urllib3", "1.26.0", ["requests"], False),
    ])
    assert [e.name for e in tr.indirect_only()] == ["urllib3"]


def test_find_normalises_hyphens():
    tr = TransitiveReport(entries=[
        TransitiveEntry("my-package", "0.1.0", [], True),
    ])
    assert tr.find("my_package") is not None


def test_find_returns_none_when_missing():
    tr = TransitiveReport(entries=[])
    assert tr.find("missing") is None


# ---------------------------------------------------------------------------
# build_transitive_report
# ---------------------------------------------------------------------------

def test_build_report_without_tree_marks_all_direct():
    r = _report("requests", "flask")
    tr = build_transitive_report(r)
    assert all(e.is_direct for e in tr.entries)


def test_build_report_with_tree_marks_indirect():
    r = _report("requests", "urllib3")
    tree = {"urllib3": ["requests"]}
    tr = build_transitive_report(r, dep_tree=tree)
    entry = tr.find("urllib3")
    assert entry is not None
    assert not entry.is_direct
    assert "requests" in entry.required_by


def test_build_report_deduplicates_across_files():
    dep = _dep("requests")
    fa1 = FileAudit(path="req.txt", deps=[dep])
    fa2 = FileAudit(path="req-dev.txt", deps=[dep])
    r = AuditReport(files=[fa1, fa2])
    tr = build_transitive_report(r)
    assert tr.total == 1


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse(*args: str) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_transitive_args(p)
    return p.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.transitive is False
    assert ns.transitive_format == "text"
    assert ns.indirect_only is False


def test_transitive_flag():
    ns = _parse("--transitive")
    assert ns.transitive is True


def test_render_text_contains_header():
    r = _report("flask")
    tr = build_transitive_report(r)
    out = _render_text(tr)
    assert "Transitive Dependency Report" in out
    assert "flask" in out


def test_render_json_is_valid():
    r = _report("flask", "requests")
    tr = build_transitive_report(r)
    out = _render_json(tr)
    data = json.loads(out)
    assert data["total"] == 2
    assert isinstance(data["entries"], list)


def test_maybe_render_returns_none_when_flag_off():
    r = _report("flask")
    ns = _parse()
    assert maybe_render_transitive(ns, r) is None


def test_maybe_render_returns_text_when_flag_on():
    r = _report("flask")
    ns = _parse("--transitive")
    out = maybe_render_transitive(ns, r)
    assert out is not None
    assert "flask" in out


def test_maybe_render_json_format():
    r = _report("flask")
    ns = _parse("--transitive", "--transitive-format", "json")
    out = maybe_render_transitive(ns, r)
    assert out is not None
    data = json.loads(out)
    assert "entries" in data
