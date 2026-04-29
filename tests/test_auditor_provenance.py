"""Tests for dep_audit.auditor_provenance."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_provenance import (
    ProvenanceEntry,
    ProvenanceReport,
    _fetch_pypi_url,
    check_provenance,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        version=version,
        latest=version,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*deps) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# ProvenanceEntry
# ---------------------------------------------------------------------------

def test_provenance_entry_to_dict_keys():
    e = ProvenanceEntry(
        name="requests", version="2.28.0",
        expected_source="pypi.org",
        actual_url="https://files.pythonhosted.org/packages/requests-2.28.0.tar.gz",
        verified=True,
    )
    d = e.to_dict()
    assert set(d.keys()) == {"name", "version", "expected_source", "actual_url", "verified"}


def test_provenance_entry_verified_true():
    e = ProvenanceEntry(
        name="flask", version="2.0.0",
        expected_source="pypi.org",
        actual_url="https://files.pythonhosted.org/packages/flask-2.0.0.tar.gz",
        verified=True,
    )
    assert e.verified is True


# ---------------------------------------------------------------------------
# ProvenanceReport
# ---------------------------------------------------------------------------

def test_provenance_report_total():
    entries = [
        ProvenanceEntry("a", "1.0", "pypi.org", "https://pypi.org/a", True),
        ProvenanceEntry("b", "2.0", "pypi.org", None, False),
    ]
    pr = ProvenanceReport(entries=entries)
    assert pr.total == 2


def test_provenance_report_unverified_count():
    entries = [
        ProvenanceEntry("a", "1.0", "pypi.org", "https://pypi.org/a", True),
        ProvenanceEntry("b", "2.0", "pypi.org", None, False),
        ProvenanceEntry("c", "3.0", "pypi.org", "https://other.com/c", False),
    ]
    pr = ProvenanceReport(entries=entries)
    assert pr.unverified_count == 2


def test_provenance_report_find_normalises_hyphens():
    e = ProvenanceEntry("my-pkg", "1.0", "pypi.org", None, False)
    pr = ProvenanceReport(entries=[e])
    assert pr.find("my_pkg") is e


def test_provenance_report_find_returns_none_when_missing():
    pr = ProvenanceReport(entries=[])
    assert pr.find("nonexistent") is None


# ---------------------------------------------------------------------------
# _fetch_pypi_url
# ---------------------------------------------------------------------------

def test_fetch_pypi_url_returns_url_from_urls_key():
    sess = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"urls": [{"url": "https://files.pythonhosted.org/pkg-1.0.tar.gz"}]}
    sess.get.return_value = resp
    url = _fetch_pypi_url("pkg", "1.0", sess)
    assert url == "https://files.pythonhosted.org/pkg-1.0.tar.gz"


def test_fetch_pypi_url_returns_none_on_error():
    sess = MagicMock()
    sess.get.side_effect = Exception("network error")
    assert _fetch_pypi_url("pkg", "1.0", sess) is None


# ---------------------------------------------------------------------------
# check_provenance
# ---------------------------------------------------------------------------

def test_check_provenance_deduplicates_packages():
    dep = _dep("requests", "2.28.0")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])

    sess = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"urls": [{"url": "https://files.pythonhosted.org/requests.tar.gz"}]}
    sess.get.return_value = resp

    prov = check_provenance(report, session=sess)
    assert prov.total == 1


def test_check_provenance_marks_verified_when_source_matches():
    dep = _dep("flask", "2.0.0")
    report = _report(dep)

    sess = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"urls": [{"url": "https://files.pythonhosted.org/flask-2.0.0.tar.gz"}]}
    sess.get.return_value = resp

    prov = check_provenance(report, expected_source="pythonhosted.org", session=sess)
    entry = prov.find("flask")
    assert entry is not None
    assert entry.verified is True


def test_check_provenance_marks_unverified_when_url_missing():
    dep = _dep("obscure-pkg", "0.1.0")
    report = _report(dep)

    sess = MagicMock()
    sess.get.side_effect = Exception("not found")

    prov = check_provenance(report, session=sess)
    entry = prov.find("obscure-pkg")
    assert entry is not None
    assert entry.verified is False
    assert entry.actual_url is None
