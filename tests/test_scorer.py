"""Tests for dep_audit.scorer and dep_audit.cli_score."""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock

import pytest

from dep_audit.scorer import score_dep, score_report, ScoredReport
from dep_audit.cli_score import add_score_args, render_scores, maybe_render_scores


def _dep(name="requests", is_outdated=False, vulns=None):
    d = MagicMock()
    d.name = name
    d.is_outdated = is_outdated
    d.vulnerabilities = vulns or []
    return d


def _vuln(vuln_id="CVE-0001", severity="high"):
    v = MagicMock()
    v.vuln_id = vuln_id
    v.severity = severity
    return v


def test_score_dep_clean():
    sd = score_dep(_dep())
    assert sd.score == 0
    assert sd.reasons == []


def test_score_dep_outdated():
    sd = score_dep(_dep(is_outdated=True))
    assert sd.score == 30
    assert "outdated" in sd.reasons


def test_score_dep_vuln_high():
    sd = score_dep(_dep(vulns=[_vuln(severity="high")]))
    assert sd.score == 60  # 40 base + 20 high


def test_score_dep_capped_at_100():
    vulns = [_vuln(severity="critical")] * 5
    sd = score_dep(_dep(is_outdated=True, vulns=vulns))
    assert sd.score == 100


def test_score_dep_reason_includes_vuln_id():
    sd = score_dep(_dep(vulns=[_vuln(vuln_id="CVE-1234", severity="medium")]))
    assert any("CVE-1234" in r for r in sd.reasons)


def _report(deps):
    file_audit = MagicMock()
    file_audit.deps = deps
    report = MagicMock()
    report.files = [file_audit]
    return report


def test_score_report_returns_scored_report():
    r = _report([_dep("flask", is_outdated=True), _dep("click")])
    sr = score_report(r)
    assert isinstance(sr, ScoredReport)
    assert len(sr.scored) == 2


def test_scored_report_top():
    r = _report([_dep("a", is_outdated=True), _dep("b"), _dep("c", vulns=[_vuln()])])
    sr = score_report(r)
    top1 = sr.top(1)
    assert len(top1) == 1


def test_scored_report_above():
    r = _report([_dep("a", is_outdated=True), _dep("b")])
    sr = score_report(r)
    assert all(s.score >= 30 for s in sr.above(30))


def _parse(args):
    p = argparse.ArgumentParser()
    add_score_args(p)
    return p.parse_args(args)


def test_add_score_args_defaults():
    ns = _parse([])
    assert ns.top is None
    assert ns.min_score == 0


def test_add_score_args_custom():
    ns = _parse(["--top", "5", "--min-score", "40"])
    assert ns.top == 5
    assert ns.min_score == 40


def test_render_scores_empty():
    sr = ScoredReport(scored=[])
    out = render_scores(sr, top=None, min_score=0)
    assert "No dependencies" in out


def test_render_scores_shows_dep():
    from dep_audit.scorer import score_dep
    sd = score_dep(_dep("requests", is_outdated=True))
    sr = ScoredReport(scored=[sd])
    out = render_scores(sr, top=None, min_score=0)
    assert "requests" in out
    assert "30" in out


def test_maybe_render_scores_none_when_defaults():
    ns = _parse([])
    sr = ScoredReport(scored=[])
    assert maybe_render_scores(ns, sr) is None


def test_maybe_render_scores_returns_str_when_top_set():
    ns = _parse(["--top", "3"])
    sr = ScoredReport(scored=[])
    result = maybe_render_scores(ns, sr)
    assert isinstance(result, str)
