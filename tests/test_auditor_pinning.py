"""Tests for dep_audit.auditor_pinning."""
from __future__ import annotations

from typing import Optional

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_pinning import (
    PinningEntry,
    PinningReport,
    _is_pinned,
    build_pinning_report,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(
    name: str,
    current: Optional[str] = "1.0.0",
    latest: Optional[str] = "1.0.0",
    raw_spec: Optional[str] = None,
) -> ResolvedDep:
    d = ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulns=VulnResult(package=name, vulnerabilities=[]),
    )
    if raw_spec is not None:
        d.raw_spec = raw_spec  # type: ignore[attr-defined]
    return d


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# _is_pinned
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec,expected", [
    ("requests==2.31.0", True),
    ("requests>=2.0", False),
    ("requests", False),
    (None, False),
    ("", False),
    ("flask==2.3.0", True),
    ("flask~=2.3", False),
    ("django!=3.0,==4.2.0", False),  # comma makes it non-simple
])
def test_is_pinned(spec, expected):
    assert _is_pinned(spec) is expected


# ---------------------------------------------------------------------------
# PinningEntry.to_dict
# ---------------------------------------------------------------------------

def test_pinning_entry_to_dict_keys():
    entry = PinningEntry(name="flask", current_version="2.3.0", raw_spec="flask==2.3.0", pinned=True)
    d = entry.to_dict()
    assert set(d.keys()) == {"name", "current_version", "raw_spec", "pinned"}


def test_pinning_entry_to_dict_values():
    entry = PinningEntry(name="flask", current_version="2.3.0", raw_spec="flask==2.3.0", pinned=True)
    d = entry.to_dict()
    assert d["name"] == "flask"
    assert d["pinned"] is True


# ---------------------------------------------------------------------------
# PinningReport properties
# ---------------------------------------------------------------------------

def test_pinning_report_total():
    r = PinningReport(entries=[
        PinningEntry("a", "1.0", "a==1.0", True),
        PinningEntry("b", "2.0", "b>=1.0", False),
    ])
    assert r.total == 2


def test_pinning_report_unpinned_count():
    r = PinningReport(entries=[
        PinningEntry("a", "1.0", "a==1.0", True),
        PinningEntry("b", "2.0", "b>=1.0", False),
        PinningEntry("c", "3.0", None, False),
    ])
    assert r.unpinned_count == 2


def test_pinning_report_pin_rate_all_pinned():
    r = PinningReport(entries=[
        PinningEntry("a", "1.0", "a==1.0", True),
        PinningEntry("b", "2.0", "b==2.0", True),
    ])
    assert r.pin_rate == 1.0


def test_pinning_report_pin_rate_none_pinned():
    r = PinningReport(entries=[
        PinningEntry("a", "1.0", "a>=1.0", False),
    ])
    assert r.pin_rate == 0.0


def test_pinning_report_pin_rate_empty():
    assert PinningReport().pin_rate == 1.0


def test_pinning_report_unpinned_filters():
    r = PinningReport(entries=[
        PinningEntry("a", "1.0", "a==1.0", True),
        PinningEntry("b", "2.0", "b>=1.0", False),
    ])
    assert [e.name for e in r.unpinned()] == ["b"]


# ---------------------------------------------------------------------------
# build_pinning_report
# ---------------------------------------------------------------------------

def test_build_pinning_report_pinned_dep():
    d = _dep("requests", current="2.31.0", raw_spec="requests==2.31.0")
    rpt = build_pinning_report(_report(d))
    assert rpt.total == 1
    assert rpt.entries[0].pinned is True


def test_build_pinning_report_unpinned_dep():
    d = _dep("flask", current="2.3.0", raw_spec="flask>=2.0")
    rpt = build_pinning_report(_report(d))
    assert rpt.entries[0].pinned is False


def test_build_pinning_report_deduplicates_across_files():
    d1 = _dep("requests", raw_spec="requests==2.31.0")
    d2 = _dep("requests", raw_spec="requests==2.31.0")
    fa1 = FileAudit(path="req1.txt", deps=[d1])
    fa2 = FileAudit(path="req2.txt", deps=[d2])
    rpt = build_pinning_report(AuditReport(files=[fa1, fa2]))
    assert rpt.total == 1


def test_build_pinning_report_to_dict_keys():
    d = _dep("click", raw_spec="click==8.1.0")
    rpt = build_pinning_report(_report(d))
    keys = set(rpt.to_dict().keys())
    assert keys == {"total", "unpinned_count", "pin_rate", "entries"}
