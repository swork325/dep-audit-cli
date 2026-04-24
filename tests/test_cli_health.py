"""Tests for dep_audit.cli_health."""
from __future__ import annotations

import argparse
import io
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.cli_health import add_health_args, maybe_render_health


def _parse(*args: str) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_health_args(p)
    return p.parse_args(list(args))


def _empty_report() -> AuditReport:
    return AuditReport(files=[])


def _dep(name="pkg", version="1.0", latest="1.0") -> ResolvedDep:
    return ResolvedDep(
        name=name, version=version, latest=latest,
        is_outdated=(version != latest), vulns=[],
    )


# --- add_health_args ---

def test_defaults():
    ns = _parse()
    assert ns.health is False
    assert ns.health_format == "text"


def test_health_flag():
    ns = _parse("--health")
    assert ns.health is True


def test_health_format_json():
    ns = _parse("--health", "--health-format", "json")
    assert ns.health_format == "json"


def test_health_format_invalid():
    with pytest.raises(SystemExit):
        _parse("--health-format", "xml")


# --- maybe_render_health ---

def test_returns_none_when_flag_not_set():
    ns = _parse()
    result = maybe_render_health(ns, _empty_report(), out=io.StringIO())
    assert result is None


def test_returns_health_score_when_flag_set():
    ns = _parse("--health")
    hs = maybe_render_health(ns, _empty_report(), out=io.StringIO())
    assert hs is not None
    assert hs.score == 100


def test_text_output_contains_grade():
    ns = _parse("--health")
    out = io.StringIO()
    maybe_render_health(ns, _empty_report(), out=out)
    assert "Grade" in out.getvalue()


def test_json_output_is_valid_json():
    ns = _parse("--health", "--health-format", "json")
    out = io.StringIO()
    maybe_render_health(ns, _empty_report(), out=out)
    data = json.loads(out.getvalue())
    assert "score" in data
    assert "grade" in data


def test_json_output_has_all_fields():
    ns = _parse("--health", "--health-format", "json")
    out = io.StringIO()
    report = AuditReport(files=[FileAudit(path="r.txt", deps=[_dep("a", "1.0", "2.0")])])
    maybe_render_health(ns, report, out=out)
    data = json.loads(out.getvalue())
    for key in ("score", "grade", "total_deps", "outdated_count", "vuln_count", "penalty"):
        assert key in data
