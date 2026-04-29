"""Tests for dep_audit.auditor_compat."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_compat import (
    CompatEntry,
    CompatReport,
    _is_compatible,
    build_compat_report,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        is_outdated=False,
        vuln_result=VulnResult(package=name, vulnerabilities=[]),
    )


def _report(*names) -> AuditReport:
    deps = [_dep(n) for n in names]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


# --- _is_compatible ---

def test_is_compatible_no_specifier():
    ok, reason = _is_compatible(None, "3.9")
    assert ok is True
    assert reason == ""


def test_is_compatible_satisfied():
    ok, reason = _is_compatible(">=3.8", "3.9")
    assert ok is True


def test_is_compatible_not_satisfied():
    ok, reason = _is_compatible(">=3.10", "3.9")
    assert ok is False
    assert "3.9" in reason


def test_is_compatible_exact_match():
    ok, _ = _is_compatible("==3.8", "3.8")
    assert ok is True


# --- CompatReport properties ---

def test_compat_report_total():
    entries = [
        CompatEntry("requests", "2.28", ">=3.7", True),
        CompatEntry("flask", "2.0", ">=3.10", False, "3.9 does not satisfy >=3.10"),
    ]
    r = CompatReport(entries=entries)
    assert r.total == 2


def test_compat_report_incompatible_count():
    entries = [
        CompatEntry("requests", "2.28", ">=3.7", True),
        CompatEntry("flask", "2.0", ">=3.10", False, "mismatch"),
    ]
    r = CompatReport(entries=entries)
    assert r.incompatible_count == 1


def test_compat_report_incompatible_list():
    entries = [
        CompatEntry("a", "1", None, True),
        CompatEntry("b", "2", ">=3.12", False, "mismatch"),
    ]
    r = CompatReport(entries=entries)
    assert len(r.incompatible) == 1
    assert r.incompatible[0].package == "b"


def test_compat_report_by_package_keys():
    entries = [CompatEntry("requests", "2.28", None, True)]
    r = CompatReport(entries=entries)
    assert "requests" in r.by_package()


# --- build_compat_report ---

def test_build_compat_report_all_compatible_when_no_extras():
    report = _report("requests", "flask")
    cr = build_compat_report(report, "3.9", {})
    assert cr.total == 2
    assert cr.incompatible_count == 0


def test_build_compat_report_flags_incompatible():
    report = _report("flask")
    extras = {"flask": ">=3.12"}
    cr = build_compat_report(report, "3.9", extras)
    assert cr.incompatible_count == 1


def test_build_compat_report_deduplicates_across_files():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    cr = build_compat_report(report, "3.9", {})
    assert cr.total == 1


def test_compat_entry_to_dict_keys():
    e = CompatEntry("requests", "2.28", ">=3.7", True)
    d = e.to_dict()
    assert set(d.keys()) == {"package", "current_version", "requires_python", "compatible", "reason"}
