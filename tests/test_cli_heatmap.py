"""Tests for dep_audit.cli_heatmap."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.cli_heatmap import add_heatmap_args, maybe_render_heatmap


def _parse(args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_heatmap_args(p)
    return p.parse_args(args)


def _dep(name: str, current: str, latest: str, vulns=None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulns=vulns or [],
    )


def _report() -> AuditReport:
    deps = [
        _dep("requests", "2.0.0", "3.0.0"),
        _dep("flask", "1.0.0", "1.0.0",
             [Vulnerability(id="CVE-1", description="x", severity="high")]),
    ]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


# --- parser defaults ---

def test_defaults():
    ns = _parse([])
    assert ns.heatmap is False
    assert ns.heatmap_format == "text"
    assert ns.heatmap_top == 0


def test_heatmap_flag():
    ns = _parse(["--heatmap"])
    assert ns.heatmap is True


def test_heatmap_format_json():
    ns = _parse(["--heatmap", "--heatmap-format", "json"])
    assert ns.heatmap_format == "json"


def test_heatmap_top():
    ns = _parse(["--heatmap", "--heatmap-top", "3"])
    assert ns.heatmap_top == 3


# --- maybe_render_heatmap ---

def test_no_output_when_flag_not_set():
    ns = _parse([])
    captured = []
    maybe_render_heatmap(ns, _report(), print_fn=captured.append)
    assert captured == []


def test_text_output_contains_header():
    ns = _parse(["--heatmap"])
    captured = []
    maybe_render_heatmap(ns, _report(), print_fn=captured.append)
    assert any("Heatmap" in line for line in captured)


def test_text_output_contains_file_path():
    ns = _parse(["--heatmap"])
    captured = []
    maybe_render_heatmap(ns, _report(), print_fn=captured.append)
    full = "\n".join(captured)
    assert "requirements.txt" in full


def test_json_output_is_valid_json():
    ns = _parse(["--heatmap", "--heatmap-format", "json"])
    captured = []
    maybe_render_heatmap(ns, _report(), print_fn=captured.append)
    data = json.loads("\n".join(captured))
    assert "entries" in data
    assert "total_score" in data


def test_json_output_entry_fields():
    ns = _parse(["--heatmap", "--heatmap-format", "json"])
    captured = []
    maybe_render_heatmap(ns, _report(), print_fn=captured.append)
    data = json.loads("\n".join(captured))
    entry = data["entries"][0]
    assert "path" in entry
    assert "score" in entry
    assert "outdated_count" in entry
    assert "vuln_count" in entry


def test_top_limits_entries():
    deps = [_dep(f"pkg{i}", "1.0", "2.0") for i in range(5)]
    files = [FileAudit(path=f"req{i}.txt", deps=[d]) for i, d in enumerate(deps)]
    report = AuditReport(files=files)
    ns = _parse(["--heatmap", "--heatmap-format", "json", "--heatmap-top", "2"])
    captured = []
    maybe_render_heatmap(ns, report, print_fn=captured.append)
    data = json.loads("\n".join(captured))
    assert len(data["entries"]) == 2
