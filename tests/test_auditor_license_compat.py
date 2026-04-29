"""Tests for dep_audit.auditor_license_compat."""
from __future__ import annotations

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.auditor_license_compat import (
    LicenseCompatEntry,
    LicenseCompatReport,
    check_license_compat,
    _is_compatible,
)


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        vulnerabilities=[],
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# _is_compatible
# ---------------------------------------------------------------------------

def test_is_compatible_unknown_license_returns_true():
    assert _is_compatible(None, "proprietary") is True


def test_is_compatible_gpl_incompatible_with_proprietary():
    assert _is_compatible("GPL-3.0", "proprietary") is False


def test_is_compatible_mit_compatible_with_proprietary():
    assert _is_compatible("MIT", "proprietary") is True


def test_is_compatible_agpl_incompatible_with_apache():
    assert _is_compatible("AGPL-3.0", "apache-2.0") is False


def test_is_compatible_gpl2_compatible_with_mit():
    # GPL-2.0 is not in the MIT blocked set
    assert _is_compatible("GPL-2.0", "mit") is True


def test_is_compatible_unknown_project_license_returns_true():
    assert _is_compatible("GPL-3.0", "bsd-3-clause") is True


# ---------------------------------------------------------------------------
# LicenseCompatReport helpers
# ---------------------------------------------------------------------------

def test_license_compat_report_total():
    entries = [
        LicenseCompatEntry("requests", "2.31.0", "Apache-2.0", "proprietary", True),
        LicenseCompatEntry("somelib", "1.0.0", "GPL-3.0", "proprietary", False),
    ]
    r = LicenseCompatReport(entries=entries)
    assert r.total == 2


def test_license_compat_report_incompatible_count():
    entries = [
        LicenseCompatEntry("a", "1.0", "MIT", "proprietary", True),
        LicenseCompatEntry("b", "1.0", "GPL-3.0", "proprietary", False),
        LicenseCompatEntry("c", "1.0", "AGPL-3.0", "proprietary", False),
    ]
    r = LicenseCompatReport(entries=entries)
    assert r.incompatible_count == 2


def test_license_compat_report_incompatible_filters():
    entries = [
        LicenseCompatEntry("a", "1.0", "MIT", "proprietary", True),
        LicenseCompatEntry("b", "1.0", "GPL-3.0", "proprietary", False),
    ]
    r = LicenseCompatReport(entries=entries)
    assert [e.package for e in r.incompatible()] == ["b"]


def test_license_compat_entry_to_dict_keys():
    e = LicenseCompatEntry("requests", "2.0", "Apache-2.0", "mit", True)
    d = e.to_dict()
    assert set(d.keys()) == {"package", "version", "dep_license", "project_license", "compatible"}


# ---------------------------------------------------------------------------
# check_license_compat integration
# ---------------------------------------------------------------------------

def test_check_license_compat_flags_gpl_in_proprietary_project():
    report = _report(_dep("django"), _dep("requests"))
    license_map = {"django": "BSD-3-Clause", "requests": "Apache-2.0"}
    result = check_license_compat(report, "proprietary", license_map)
    assert result.incompatible_count == 0


def test_check_license_compat_flags_gpl():
    report = _report(_dep("somelib"), _dep("requests"))
    license_map = {"somelib": "GPL-3.0", "requests": "Apache-2.0"}
    result = check_license_compat(report, "proprietary", license_map)
    assert result.incompatible_count == 1
    assert result.incompatible()[0].package == "somelib"


def test_check_license_compat_deduplicates_across_files():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    result = check_license_compat(report, "proprietary", {"requests": "GPL-3.0"})
    assert result.total == 1


def test_check_license_compat_unknown_license_not_flagged():
    report = _report(_dep("mystery"))
    result = check_license_compat(report, "proprietary", {})
    assert result.incompatible_count == 0
