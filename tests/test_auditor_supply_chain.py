"""Tests for dep_audit.auditor_supply_chain."""
from __future__ import annotations

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.auditor_supply_chain import (
    _edit_distance,
    _is_typosquat_candidate,
    _check_against,
    SupplyChainEntry,
    SupplyChainReport,
    build_supply_chain_report,
)


def _dep(name: str, current: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=current, vulns=[])


def _report(*pairs) -> AuditReport:
    """Build an AuditReport from (path, [dep, ...]) pairs."""
    files = [
        FileAudit(path=p, deps=list(deps))
        for p, deps in pairs
    ]
    return AuditReport(files=files)


# ── _edit_distance ────────────────────────────────────────────────────────────

def test_edit_distance_identical():
    assert _edit_distance("requests", "requests") == 0


def test_edit_distance_one_char():
    assert _edit_distance("flask", "flaask") == 1


def test_edit_distance_completely_different():
    assert _edit_distance("abc", "xyz") == 3


# ── _check_against ────────────────────────────────────────────────────────────

def test_check_against_exact_match_returns_none():
    known = frozenset({"requests"})
    assert _check_against("requests", known, threshold=2) is None


def test_check_against_typo_detected():
    known = frozenset({"requests"})
    result = _check_against("requsets", known, threshold=2)
    assert result == "requests"


def test_check_against_unrelated_returns_none():
    known = frozenset({"requests"})
    assert _check_against("zxqwerty", known, threshold=2) is None


# ── _is_typosquat_candidate ───────────────────────────────────────────────────

def test_is_typosquat_candidate_known_package_returns_none():
    assert _is_typosquat_candidate("requests") is None


def test_is_typosquat_candidate_detects_typo():
    result = _is_typosquat_candidate("requsets")
    assert result == "requests"


# ── SupplyChainReport ─────────────────────────────────────────────────────────

def test_supply_chain_report_total():
    entries = [
        SupplyChainEntry(package="a", version="1.0"),
        SupplyChainEntry(package="b", version="2.0", suspicious=True, typosquat_of="requests"),
    ]
    rpt = SupplyChainReport(entries=entries)
    assert rpt.total == 2


def test_supply_chain_report_suspicious_count():
    entries = [
        SupplyChainEntry(package="a", version="1.0"),
        SupplyChainEntry(package="b", version="2.0", suspicious=True, typosquat_of="requests"),
    ]
    rpt = SupplyChainReport(entries=entries)
    assert rpt.suspicious_count == 1


def test_supply_chain_report_suspicious_entries():
    entries = [
        SupplyChainEntry(package="a", version="1.0"),
        SupplyChainEntry(package="b", version="2.0", suspicious=True, typosquat_of="flask"),
    ]
    rpt = SupplyChainReport(entries=entries)
    assert len(rpt.suspicious_entries()) == 1
    assert rpt.suspicious_entries()[0].package == "b"


# ── build_supply_chain_report ─────────────────────────────────────────────────

def test_build_supply_chain_report_clean_dep_not_suspicious():
    report = _report(("req.txt", [_dep("requests", "2.28.0")]))
    sc = build_supply_chain_report(report)
    assert sc.suspicious_count == 0


def test_build_supply_chain_report_typo_dep_is_suspicious():
    report = _report(("req.txt", [_dep("requsets", "1.0.0")]))
    sc = build_supply_chain_report(report)
    assert sc.suspicious_count == 1
    assert sc.entries[0].typosquat_of == "requests"


def test_build_supply_chain_report_deduplicates_packages():
    dep = _dep("requsets", "1.0.0")
    report = _report(
        ("a/req.txt", [dep]),
        ("b/req.txt", [dep]),
    )
    sc = build_supply_chain_report(report)
    assert sc.total == 1


def test_supply_chain_entry_to_dict():
    e = SupplyChainEntry(package="requsets", version="1.0", typosquat_of="requests", suspicious=True)
    d = e.to_dict()
    assert d["package"] == "requsets"
    assert d["typosquat_of"] == "requests"
    assert d["suspicious"] is True
