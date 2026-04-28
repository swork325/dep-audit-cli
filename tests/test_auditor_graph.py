"""Tests for dep_audit.auditor_graph and dep_audit.cli_graph."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_graph import (
    DependencyGraph,
    GraphNode,
    build_graph,
    _normalise,
)
from dep_audit.cli_graph import (
    add_graph_args,
    maybe_render_graph,
    _render_text,
    _render_json,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=current != latest,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*dep_lists: list) -> AuditReport:
    files = [
        FileAudit(path=f"req{i}.txt", deps=deps)
        for i, deps in enumerate(dep_lists)
    ]
    return AuditReport(files=files)


# ---------------------------------------------------------------------------
# GraphNode
# ---------------------------------------------------------------------------

def test_graph_node_to_dict():
    node = GraphNode(name="requests", dependents=["myapp"], dependencies=["urllib3"])
    d = node.to_dict()
    assert d["name"] == "requests"
    assert d["dependents"] == ["myapp"]
    assert d["dependencies"] == ["urllib3"]


# ---------------------------------------------------------------------------
# build_graph
# ---------------------------------------------------------------------------

def test_build_graph_creates_node_per_dep():
    report = _report([_dep("requests"), _dep("flask")])
    graph = build_graph(report)
    assert "requests" in graph.nodes
    assert "flask" in graph.nodes


def test_build_graph_deduplicates_across_files():
    report = _report([_dep("requests")], [_dep("requests")])
    graph = build_graph(report)
    assert graph.total == 1


def test_build_graph_extras_wires_edges():
    report = _report([_dep("requests"), _dep("urllib3")])
    extras = {"requests": ["urllib3"]}
    graph = build_graph(report, extras=extras)
    assert "urllib3" in graph.nodes["requests"].dependencies
    assert "requests" in graph.nodes["urllib3"].dependents


def test_build_graph_extras_adds_unknown_packages():
    report = _report([_dep("requests")])
    extras = {"requests": ["certifi"]}
    graph = build_graph(report, extras=extras)
    assert "certifi" in graph.nodes


def test_roots_returns_packages_with_no_dependents():
    report = _report([_dep("requests"), _dep("urllib3")])
    extras = {"requests": ["urllib3"]}
    graph = build_graph(report, extras=extras)
    assert "requests" in graph.roots()
    assert "urllib3" not in graph.roots()


def test_leaves_returns_packages_with_no_dependencies():
    report = _report([_dep("requests"), _dep("urllib3")])
    extras = {"requests": ["urllib3"]}
    graph = build_graph(report, extras=extras)
    assert "urllib3" in graph.leaves()
    assert "requests" not in graph.leaves()


def test_find_normalises_hyphens():
    report = _report([_dep("my-package")])
    graph = build_graph(report)
    assert graph.find("my-package") is not None
    assert graph.find("my_package") is not None


# ---------------------------------------------------------------------------
# cli helpers
# ---------------------------------------------------------------------------

def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_graph_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.graph is False
    assert ns.graph_format == "text"
    assert ns.graph_root is None


def test_graph_flag():
    ns = _parse("--graph")
    assert ns.graph is True


def test_graph_format_json():
    ns = _parse("--graph", "--graph-format", "json")
    assert ns.graph_format == "json"


def test_maybe_render_graph_skipped_when_flag_false(capsys):
    report = _report([_dep("flask")])
    ns = _parse()
    captured: list[str] = []
    maybe_render_graph(ns, report, print_fn=captured.append)
    assert captured == []


def test_maybe_render_graph_text_output():
    report = _report([_dep("flask")])
    ns = _parse("--graph")
    captured: list[str] = []
    maybe_render_graph(ns, report, print_fn=captured.append)
    assert captured
    assert "flask" in captured[0]


def test_maybe_render_graph_json_output():
    report = _report([_dep("flask")])
    ns = _parse("--graph", "--graph-format", "json")
    captured: list[str] = []
    maybe_render_graph(ns, report, print_fn=captured.append)
    data = json.loads(captured[0])
    assert "nodes" in data
    assert "flask" in data["nodes"]


def test_render_text_contains_total():
    report = _report([_dep("requests"), _dep("flask")])
    graph = build_graph(report)
    text = _render_text(graph, root=None)
    assert "Total packages: 2" in text
