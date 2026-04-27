"""Tests for dep_audit.tracer and dep_audit.cli_tracer."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.tracer import TraceNode, TraceReport, build_trace
from dep_audit.cli_tracer import (
    add_tracer_args,
    _render_text,
    _render_json,
    maybe_render_tracer,
)


def _dep(name: str, current: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current=current, latest=current, vulnerabilities=[])


def _report(*dep_lists) -> AuditReport:
    files = [
        FileAudit(path=f"req{i}.txt", deps=list(deps))
        for i, deps in enumerate(dep_lists)
    ]
    return AuditReport(files=files)


# --- TraceReport ----------------------------------------------------------

def test_trace_report_total():
    tr = TraceReport(nodes=[TraceNode("requests", "2.28.0"), TraceNode("flask", "2.0.0")])
    assert tr.total() == 2


def test_trace_report_find_by_name():
    node = TraceNode("requests", "2.28.0")
    tr = TraceReport(nodes=[node])
    assert tr.find("requests") is node


def test_trace_report_find_normalises_hyphens():
    node = TraceNode("my-package", "1.0")
    tr = TraceReport(nodes=[node])
    assert tr.find("my_package") is node


def test_trace_report_find_returns_none_when_missing():
    tr = TraceReport(nodes=[])
    assert tr.find("unknown") is None


def test_trace_report_transitive_filters_correctly():
    direct = TraceNode("flask", "2.0.0")
    transitive = TraceNode("werkzeug", "2.0.0", required_by=["flask"])
    tr = TraceReport(nodes=[direct, transitive])
    assert tr.transitive() == [transitive]
    assert tr.direct() == [direct]


# --- build_trace ----------------------------------------------------------

def test_build_trace_creates_node_per_unique_dep():
    report = _report([_dep("requests"), _dep("flask")])
    trace = build_trace(report)
    assert trace.total() == 2


def test_build_trace_deduplicates_across_files():
    report = _report([_dep("requests")], [_dep("requests")])
    trace = build_trace(report)
    assert trace.total() == 1


def test_build_trace_applies_extras():
    report = _report([_dep("werkzeug")])
    trace = build_trace(report, extras={"werkzeug": ["flask"]})
    node = trace.find("werkzeug")
    assert node is not None
    assert node.required_by == ["flask"]


def test_build_trace_direct_dep_has_no_parents():
    report = _report([_dep("flask")])
    trace = build_trace(report)
    node = trace.find("flask")
    assert node is not None
    assert node.required_by == []


# --- CLI rendering --------------------------------------------------------

def _parse(*args) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_tracer_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.trace is False
    assert ns.trace_format == "text"
    assert ns.trace_only_transitive is False


def test_trace_flag():
    ns = _parse("--trace")
    assert ns.trace is True


def test_render_text_contains_dep_name():
    report = _report([_dep("requests", "2.28.0")])
    trace = build_trace(report)
    out = _render_text(trace, only_transitive=False)
    assert "requests" in out
    assert "2.28.0" in out


def test_render_text_only_transitive_excludes_direct():
    report = _report([_dep("flask")])
    trace = build_trace(report)
    out = _render_text(trace, only_transitive=True)
    assert "flask" not in out


def test_render_json_is_valid():
    report = _report([_dep("flask", "2.0.0")])
    trace = build_trace(report)
    data = json.loads(_render_json(trace, only_transitive=False))
    assert isinstance(data, list)
    assert data[0]["name"] == "flask"


def test_maybe_render_tracer_skips_when_flag_not_set(capsys):
    report = _report([_dep("flask")])
    ns = _parse()
    maybe_render_tracer(ns, report)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_maybe_render_tracer_prints_when_flag_set(capsys):
    report = _report([_dep("flask")])
    ns = _parse("--trace")
    maybe_render_tracer(ns, report)
    captured = capsys.readouterr()
    assert "flask" in captured.out
