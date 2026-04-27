"""Tests for dep_audit.heatmap."""
from __future__ import annotations

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.heatmap import HeatmapEntry, Heatmap, _score_file, build_heatmap


def _dep(
    name: str = "pkg",
    current: str = "1.0.0",
    latest: str | None = None,
    vulns: list | None = None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest or current,
        vulns=vulns or [],
    )


def _vuln(severity: str = "high") -> Vulnerability:
    return Vulnerability(id="CVE-0000", description="desc", severity=severity)


def _file(path: str, deps: list) -> FileAudit:
    return FileAudit(path=path, deps=deps)


# --- HeatmapEntry ---

def test_heatmap_entry_to_dict():
    entry = HeatmapEntry(path="req.txt", score=15, outdated_count=2, vuln_count=1)
    d = entry.to_dict()
    assert d["path"] == "req.txt"
    assert d["score"] == 15
    assert d["outdated_count"] == 2
    assert d["vuln_count"] == 1


# --- _score_file ---

def test_score_file_clean_dep_is_zero():
    fa = _file("req.txt", [_dep("requests", "2.0.0", "2.0.0")])
    entry = _score_file(fa)
    assert entry.score == 0
    assert entry.outdated_count == 0
    assert entry.vuln_count == 0


def test_score_file_outdated_adds_weight():
    fa = _file("req.txt", [_dep("requests", "1.0.0", "2.0.0")])
    entry = _score_file(fa)
    assert entry.score == 3
    assert entry.outdated_count == 1


def test_score_file_high_vuln_adds_weight():
    fa = _file("req.txt", [_dep("flask", "1.0.0", "1.0.0", [_vuln("high")])])
    entry = _score_file(fa)
    assert entry.score == 20
    assert entry.vuln_count == 1


def test_score_file_critical_vuln_adds_weight():
    fa = _file("req.txt", [_dep("flask", "1.0.0", "1.0.0", [_vuln("critical")])])
    entry = _score_file(fa)
    assert entry.score == 40


def test_score_file_combined_outdated_and_vuln():
    dep = _dep("pkg", "1.0.0", "2.0.0", [_vuln("medium")])
    fa = _file("req.txt", [dep])
    entry = _score_file(fa)
    assert entry.score == 3 + 10  # outdated + medium


# --- build_heatmap ---

def test_build_heatmap_sorted_hottest_first():
    cold = _file("cold.txt", [_dep("a", "1.0", "1.0")])
    hot = _file("hot.txt", [_dep("b", "1.0", "2.0", [_vuln("critical")])])
    report = AuditReport(files=[cold, hot])
    hm = build_heatmap(report)
    assert hm.entries[0].path == "hot.txt"
    assert hm.entries[1].path == "cold.txt"


def test_build_heatmap_total_score():
    fa = _file("req.txt", [_dep("x", "1.0", "2.0")])
    report = AuditReport(files=[fa])
    hm = build_heatmap(report)
    assert hm.total_score == 3


def test_build_heatmap_hottest_none_when_empty():
    report = AuditReport(files=[])
    hm = build_heatmap(report)
    assert hm.hottest is None


def test_build_heatmap_hottest_returns_first_entry():
    fa = _file("req.txt", [_dep("x", "1.0", "2.0")])
    report = AuditReport(files=[fa])
    hm = build_heatmap(report)
    assert hm.hottest is not None
    assert hm.hottest.path == "req.txt"
