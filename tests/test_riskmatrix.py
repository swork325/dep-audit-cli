"""Tests for dep_audit.riskmatrix and dep_audit.cli_riskmatrix."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.riskmatrix import (
    RiskCell,
    RiskMatrix,
    _highest_severity,
    build_risk_matrix,
)
from dep_audit.cli_riskmatrix import (
    add_riskmatrix_args,
    maybe_render_riskmatrix,
    _render_text,
    _render_json,
)


def _vuln(severity: str) -> Vulnerability:
    return Vulnerability(id="CVE-0000", description="x", severity=severity)


def _dep(name: str, *, outdated: bool = False, vulns=()) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version="1.0.0",
        latest_version="2.0.0" if outdated else "1.0.0",
        is_outdated=outdated,
        vulns=list(vulns),
    )


def _report(*file_audits: FileAudit) -> AuditReport:
    return AuditReport(files=list(file_audits))


def _fa(path: str, *deps: ResolvedDep) -> FileAudit:
    return FileAudit(path=path, deps=list(deps))


# --- _highest_severity ---

def test_highest_severity_no_vulns():
    assert _highest_severity(_dep("x")) == "none"


def test_highest_severity_single():
    assert _highest_severity(_dep("x", vulns=[_vuln("high")])) == "high"


def test_highest_severity_picks_max():
    d = _dep("x", vulns=[_vuln("low"), _vuln("critical"), _vuln("medium")])
    assert _highest_severity(d) == "critical"


def test_highest_severity_unknown_treated_as_none():
    d = _dep("x", vulns=[_vuln("banana")])
    assert _highest_severity(d) == "none"


# --- build_risk_matrix ---

def test_build_risk_matrix_ok_dep():
    report = _report(_fa("req.txt", _dep("flask")))
    matrix = build_risk_matrix(report)
    assert matrix.total() == 1
    assert matrix.cells[0].risk == "ok"


def test_build_risk_matrix_outdated_no_vuln_is_low():
    report = _report(_fa("req.txt", _dep("flask", outdated=True)))
    matrix = build_risk_matrix(report)
    assert matrix.cells[0].risk == "low"


def test_build_risk_matrix_current_high_vuln_is_high():
    report = _report(_fa("req.txt", _dep("flask", vulns=[_vuln("high")])))
    matrix = build_risk_matrix(report)
    assert matrix.cells[0].risk == "high"


def test_build_risk_matrix_outdated_high_vuln_is_critical():
    report = _report(_fa("req.txt", _dep("flask", outdated=True, vulns=[_vuln("high")])))
    matrix = build_risk_matrix(report)
    assert matrix.cells[0].risk == "critical"


def test_build_risk_matrix_deduplicates_packages():
    d1 = _dep("requests", outdated=False)
    d2 = _dep("requests", outdated=True)
    report = _report(_fa("a.txt", d1), _fa("b.txt", d2))
    matrix = build_risk_matrix(report)
    assert matrix.total() == 1
    assert matrix.cells[0].outdated_level == "outdated"


def test_build_risk_matrix_source_files_collected():
    d = _dep("requests")
    report = _report(_fa("a.txt", d), _fa("b.txt", d))
    matrix = build_risk_matrix(report)
    assert set(matrix.cells[0].source_files) == {"a.txt", "b.txt"}


def test_critical_helper():
    d = _dep("x", outdated=True, vulns=[_vuln("critical")])
    report = _report(_fa("r.txt", d))
    matrix = build_risk_matrix(report)
    assert len(matrix.critical()) == 1


# --- cli_riskmatrix ---

def _parse(*args) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_riskmatrix_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.risk_matrix is False
    assert ns.risk_matrix_format == "text"
    assert ns.risk_min == "low"


def test_risk_matrix_flag():
    ns = _parse("--risk-matrix")
    assert ns.risk_matrix is True


def test_maybe_render_riskmatrix_returns_none_when_flag_off():
    ns = _parse()
    report = _report(_fa("r.txt", _dep("flask")))
    assert maybe_render_riskmatrix(ns, report) is None


def test_maybe_render_riskmatrix_returns_text():
    ns = _parse("--risk-matrix")
    report = _report(_fa("r.txt", _dep("flask", outdated=True)))
    output = maybe_render_riskmatrix(ns, report)
    assert output is not None
    assert "Risk Matrix" in output
    assert "flask" in output


def test_maybe_render_riskmatrix_json_valid():
    ns = _parse("--risk-matrix", "--risk-matrix-format", "json")
    report = _report(_fa("r.txt", _dep("flask", outdated=True)))
    output = maybe_render_riskmatrix(ns, report)
    data = json.loads(output)
    assert isinstance(data, list)
    assert data[0]["package"] == "flask"


def test_render_text_respects_min_risk():
    matrix = RiskMatrix(cells=[
        RiskCell("a", "current", "none", "ok", ["r.txt"]),
        RiskCell("b", "outdated", "none", "low", ["r.txt"]),
    ])
    text = _render_text(matrix, min_risk="low")
    assert "b" in text
    assert "a" not in text
