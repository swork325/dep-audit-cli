"""Tests for dep_audit.auditor_churn."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_churn import ChurnEntry, ChurnReport, build_churn_report
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import VulnResult


def _dep(name: str, current: str = "1.0.0", latest: str = "2.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulnerabilities=VulnResult(package=name, vulns=[]),
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# --- ChurnEntry ---

def test_churn_entry_to_dict_keys():
    e = ChurnEntry(name="requests", current_version="2.0", latest_version="3.0",
                   change_count=4, is_frequent=True)
    d = e.to_dict()
    assert set(d) == {"name", "current_version", "latest_version", "change_count", "is_frequent"}


def test_churn_entry_to_dict_values():
    e = ChurnEntry(name="flask", current_version="1.0", latest_version="2.0",
                   change_count=2, is_frequent=False)
    d = e.to_dict()
    assert d["name"] == "flask"
    assert d["change_count"] == 2
    assert d["is_frequent"] is False


# --- ChurnReport ---

def test_churn_report_total():
    entries = [ChurnEntry("a", "1", "2", 1, False), ChurnEntry("b", "1", "2", 5, True)]
    cr = ChurnReport(entries=entries)
    assert cr.total == 2


def test_churn_report_frequent_count():
    entries = [
        ChurnEntry("a", "1", "2", 1, False),
        ChurnEntry("b", "1", "2", 5, True),
        ChurnEntry("c", "1", "2", 3, True),
    ]
    cr = ChurnReport(entries=entries)
    assert cr.frequent_count == 2


def test_churn_report_find_by_name():
    entries = [ChurnEntry("requests", "2.0", "3.0", 4, True)]
    cr = ChurnReport(entries=entries)
    assert cr.find("requests") is not None
    assert cr.find("flask") is None


def test_churn_report_find_normalises_hyphens():
    entries = [ChurnEntry("my-pkg", "1.0", "2.0", 2, False)]
    cr = ChurnReport(entries=entries)
    assert cr.find("my_pkg") is not None


def test_churn_report_frequent_filters():
    entries = [
        ChurnEntry("a", "1", "2", 1, False),
        ChurnEntry("b", "1", "2", 5, True),
    ]
    cr = ChurnReport(entries=entries)
    assert len(cr.frequent()) == 1
    assert cr.frequent()[0].name == "b"


# --- build_churn_report ---

def test_build_churn_report_uses_history():
    dep = _dep("requests", "2.28.0", "2.31.0")
    rpt = _report(dep)
    history = {"requests": 5}
    cr = build_churn_report(rpt, history, threshold=3)
    entry = cr.find("requests")
    assert entry is not None
    assert entry.change_count == 5
    assert entry.is_frequent is True


def test_build_churn_report_zero_when_not_in_history():
    dep = _dep("flask", "2.0.0", "3.0.0")
    rpt = _report(dep)
    cr = build_churn_report(rpt, {}, threshold=3)
    entry = cr.find("flask")
    assert entry is not None
    assert entry.change_count == 0
    assert entry.is_frequent is False


def test_build_churn_report_deduplicates_across_files():
    dep = _dep("requests")
    fa1 = FileAudit(path="req1.txt", deps=[dep])
    fa2 = FileAudit(path="req2.txt", deps=[dep])
    rpt = AuditReport(files=[fa1, fa2])
    cr = build_churn_report(rpt, {}, threshold=3)
    assert cr.total == 1


def test_build_churn_report_sorted_by_change_count_descending():
    deps = [_dep("a"), _dep("b"), _dep("c")]
    rpt = _report(*deps)
    history = {"a": 1, "b": 5, "c": 3}
    cr = build_churn_report(rpt, history, threshold=10)
    assert cr.entries[0].name == "b"
    assert cr.entries[1].name == "c"
    assert cr.entries[2].name == "a"
