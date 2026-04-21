"""Tests for dep_audit.digester and dep_audit.cli_digest."""
from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.digester import ReportDigest, compute_digest, digests_match
from dep_audit.cli_digest import add_digest_args, maybe_print_digest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dep(name: str, installed="1.0.0", latest="2.0.0", vulns=None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        installed_version=installed,
        latest_version=latest,
        vulns=vulns or [],
    )


def _report(*file_specs) -> AuditReport:
    """Build an AuditReport from (path, [dep, ...]) pairs."""
    files = [
        FileAudit(path=Path(p), deps=deps)
        for p, deps in file_specs
    ]
    return AuditReport(files=files)


# ---------------------------------------------------------------------------
# digester tests
# ---------------------------------------------------------------------------

def test_compute_digest_returns_report_digest():
    r = _report(("req.txt", [_dep("flask")]))
    d = compute_digest(r)
    assert isinstance(d, ReportDigest)
    assert len(d.hex) == 64  # SHA-256 hex


def test_compute_digest_entry_count():
    r = _report(("req.txt", [_dep("flask"), _dep("requests")]))
    d = compute_digest(r)
    assert d.entry_count == 2


def test_same_reports_produce_same_digest():
    r1 = _report(("req.txt", [_dep("flask", "1.0", "2.0")]))
    r2 = _report(("req.txt", [_dep("flask", "1.0", "2.0")]))
    assert compute_digest(r1).hex == compute_digest(r2).hex


def test_different_versions_produce_different_digest():
    r1 = _report(("req.txt", [_dep("flask", "1.0", "2.0")]))
    r2 = _report(("req.txt", [_dep("flask", "1.1", "2.0")]))
    assert compute_digest(r1).hex != compute_digest(r2).hex


def test_digests_match_helper_true():
    r1 = _report(("req.txt", [_dep("django")]))
    r2 = _report(("req.txt", [_dep("django")]))
    assert digests_match(r1, r2) is True


def test_digests_match_helper_false():
    r1 = _report(("req.txt", [_dep("django")]))
    r2 = _report(("req.txt", [_dep("flask")]))
    assert digests_match(r1, r2) is False


def test_short_digest_length():
    r = _report(("req.txt", [_dep("flask")]))
    d = compute_digest(r)
    assert d.short(8) == d.hex[:8]
    assert d.short() == d.hex[:12]


def test_empty_report_is_stable():
    r1 = _report()
    r2 = _report()
    assert digests_match(r1, r2) is True
    assert compute_digest(r1).entry_count == 0


# ---------------------------------------------------------------------------
# cli_digest tests
# ---------------------------------------------------------------------------

def _parse(*args):
    parser = argparse.ArgumentParser()
    add_digest_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    assert ns.digest is False
    assert ns.digest_short is False
    assert ns.digest_length == 12


def test_digest_flag():
    ns = _parse("--digest")
    assert ns.digest is True


def test_digest_short_flag():
    ns = _parse("--digest-short")
    assert ns.digest_short is True


def test_maybe_print_digest_no_flag_returns_none():
    ns = _parse()
    r = _report(("req.txt", [_dep("flask")]))
    result = maybe_print_digest(ns, r, out=io.StringIO())
    assert result is None


def test_maybe_print_digest_full():
    ns = _parse("--digest")
    r = _report(("req.txt", [_dep("flask")]))
    buf = io.StringIO()
    result = maybe_print_digest(ns, r, out=buf)
    assert result is not None
    output = buf.getvalue()
    assert "digest:" in output
    assert len(result.hex) == 64


def test_maybe_print_digest_short_output():
    ns = _parse("--digest-short", "--digest-length", "8")
    r = _report(("req.txt", [_dep("flask")]))
    buf = io.StringIO()
    result = maybe_print_digest(ns, r, out=buf)
    output = buf.getvalue()
    short = result.short(8)
    assert short in output
    assert len(short) == 8
