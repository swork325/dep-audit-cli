"""Tests for dep_audit.classifier."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dep_audit.classifier import (
    ClassificationReport,
    RiskTier,
    _classify_dep,
    classify_report,
)


def _dep(
    name="requests",
    installed="2.0.0",
    latest="2.0.0",
    is_outdated=False,
    vulns=None,
    raw_line=None,
):
    d = MagicMock()
    d.name = name
    d.installed_version = installed
    d.latest_version = latest
    d.is_outdated = is_outdated
    d.vulnerabilities = vulns or []
    d.raw_line = raw_line or f"{name}=={installed}"
    return d


def _vuln(severity="high"):
    v = MagicMock()
    v.severity = severity
    return v


# --- _classify_dep ---

def test_clean_dep_returns_clean_tier():
    dep = _dep()
    result = _classify_dep(dep)
    assert result.tier == RiskTier.CLEAN


def test_outdated_dep_returns_medium_tier():
    dep = _dep(is_outdated=True)
    result = _classify_dep(dep)
    assert result.tier == RiskTier.MEDIUM
    assert "outdated" in result.reasons


def test_high_severity_vuln_returns_critical_tier():
    dep = _dep(vulns=[_vuln("high")])
    result = _classify_dep(dep)
    assert result.tier == RiskTier.CRITICAL


def test_critical_severity_vuln_returns_critical_tier():
    dep = _dep(vulns=[_vuln("critical")])
    result = _classify_dep(dep)
    assert result.tier == RiskTier.CRITICAL


def test_medium_severity_vuln_returns_high_tier():
    dep = _dep(vulns=[_vuln("medium")])
    result = _classify_dep(dep)
    assert result.tier == RiskTier.HIGH


def test_outdated_and_high_vuln_still_critical():
    dep = _dep(is_outdated=True, vulns=[_vuln("high")])
    result = _classify_dep(dep)
    assert result.tier == RiskTier.CRITICAL
    assert "outdated" in result.reasons


def test_unpinned_dep_returns_low_tier():
    dep = _dep(raw_line="requests>=1.0")
    result = _classify_dep(dep)
    assert result.tier == RiskTier.LOW
    assert "unpinned" in result.reasons


# --- classify_report ---

def _make_report(*deps):
    file_audit = MagicMock()
    file_audit.deps = list(deps)
    report = MagicMock()
    report.files = [file_audit]
    return report


def test_classify_report_returns_classification_report():
    report = _make_report(_dep())
    result = classify_report(report)
    assert isinstance(result, ClassificationReport)


def test_classify_report_total_matches_dep_count():
    report = _make_report(_dep(), _dep(name="flask", is_outdated=True))
    result = classify_report(report)
    assert result.total() == 2


def test_classify_report_critical_count():
    report = _make_report(
        _dep(vulns=[_vuln("critical")]),
        _dep(name="flask"),
    )
    result = classify_report(report)
    assert result.critical_count() == 1


def test_classify_report_empty_report():
    report = _make_report()
    result = classify_report(report)
    assert result.total() == 0
    assert result.critical_count() == 0
