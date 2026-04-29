"""Tests for dep_audit.cli_provenance."""
from __future__ import annotations

import argparse
import io
import json
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_provenance import ProvenanceEntry, ProvenanceReport
from dep_audit.cli_provenance import (
    _render_json,
    _render_text,
    add_provenance_args,
    maybe_render_provenance,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str = "requests", version: str = "2.28.0") -> ResolvedDep:
    return ResolvedDep(
        name=name, version=version, latest=version,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*deps) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def _parse(args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_provenance_args(p)
    return p.parse_args(args)


def _prov(verified=True) -> ProvenanceReport:
    e = ProvenanceEntry(
        name="requests", version="2.28.0",
        expected_source="pypi.org",
        actual_url="https://files.pythonhosted.org/requests.tar.gz",
        verified=verified,
    )
    return ProvenanceReport(entries=[e])


# ---------------------------------------------------------------------------
# Parser defaults
# ---------------------------------------------------------------------------

def test_defaults():
    ns = _parse([])
    assert ns.provenance is False
    assert ns.provenance_source == "pypi.org"
    assert ns.provenance_format == "text"


def test_provenance_flag():
    ns = _parse(["--provenance"])
    assert ns.provenance is True


def test_provenance_source_custom():
    ns = _parse(["--provenance-source", "example.com"])
    assert ns.provenance_source == "example.com"


def test_provenance_format_json():
    ns = _parse(["--provenance-format", "json"])
    assert ns.provenance_format == "json"


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_contains_header():
    text = _render_text(_prov(verified=True))
    assert "Provenance Report" in text


def test_render_text_shows_all_verified_message():
    text = _render_text(_prov(verified=True))
    assert "All packages verified" in text


def test_render_text_shows_unverified_package():
    text = _render_text(_prov(verified=False))
    assert "requests" in text
    assert "Unverified packages" in text


# ---------------------------------------------------------------------------
# _render_json
# ---------------------------------------------------------------------------

def test_render_json_structure():
    data = json.loads(_render_json(_prov()))
    assert "total" in data
    assert "unverified_count" in data
    assert "entries" in data


def test_render_json_entry_fields():
    data = json.loads(_render_json(_prov()))
    entry = data["entries"][0]
    assert set(entry.keys()) == {"name", "version", "expected_source", "actual_url", "verified"}


# ---------------------------------------------------------------------------
# maybe_render_provenance
# ---------------------------------------------------------------------------

def test_maybe_render_provenance_skips_when_flag_false():
    ns = _parse([])
    report = _report(_dep())
    result = maybe_render_provenance(ns, report, out=io.StringIO())
    assert result is None


def test_maybe_render_provenance_returns_report_when_flag_set():
    ns = _parse(["--provenance"])
    report = _report(_dep())
    prov_mock = _prov()
    with patch("dep_audit.cli_provenance.check_provenance", return_value=prov_mock):
        result = maybe_render_provenance(ns, report, out=io.StringIO())
    assert isinstance(result, ProvenanceReport)


def test_maybe_render_provenance_writes_json_when_requested():
    ns = _parse(["--provenance", "--provenance-format", "json"])
    report = _report(_dep())
    prov_mock = _prov()
    buf = io.StringIO()
    with patch("dep_audit.cli_provenance.check_provenance", return_value=prov_mock):
        maybe_render_provenance(ns, report, out=buf)
    output = buf.getvalue()
    data = json.loads(output)
    assert "entries" in data
