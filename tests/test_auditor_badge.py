"""Tests for dep_audit.auditor_badge."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_badge import BadgeData, _build_message, _pick_color, build_badge
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability


def _dep(
    name: str = "pkg",
    installed: str = "1.0.0",
    latest: str | None = "1.0.0",
    vulns: list | None = None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        installed_version=installed,
        latest_version=latest,
        vulns=vulns or [],
    )


def _report(*file_audits: FileAudit) -> AuditReport:
    return AuditReport(file_audits=list(file_audits))


# --- _pick_color ---

def test_pick_color_all_clean():
    assert _pick_color(0, 0) == "brightgreen"


def test_pick_color_one_outdated():
    assert _pick_color(1, 0) == "green"


def test_pick_color_five_outdated():
    assert _pick_color(5, 0) == "yellow"


def test_pick_color_ten_outdated():
    assert _pick_color(10, 0) == "orange"


def test_pick_color_any_vuln_is_red():
    assert _pick_color(0, 1) == "red"
    assert _pick_color(20, 3) == "red"


# --- _build_message ---

def test_build_message_clean():
    assert _build_message(0, 0) == "up to date"


def test_build_message_outdated_only():
    assert "outdated" in _build_message(3, 0)
    assert "3" in _build_message(3, 0)


def test_build_message_vuln_only():
    assert "vuln" in _build_message(0, 2)


def test_build_message_both():
    msg = _build_message(4, 1)
    assert "vuln" in msg
    assert "outdated" in msg


# --- build_badge ---

def test_build_badge_clean_report():
    fa = FileAudit(path="req.txt", deps=[_dep()])
    badge = build_badge(_report(fa))
    assert isinstance(badge, BadgeData)
    assert badge.color == "brightgreen"
    assert badge.message == "up to date"


def test_build_badge_with_outdated():
    dep = _dep(installed="1.0.0", latest="2.0.0")
    fa = FileAudit(path="req.txt", deps=[dep])
    badge = build_badge(_report(fa))
    assert badge.color == "green"


def test_build_badge_with_vuln():
    v = Vulnerability(id="CVE-1", description="bad", severity="high", fix_version="2.0")
    dep = _dep(vulns=[v])
    fa = FileAudit(path="req.txt", deps=[dep])
    badge = build_badge(_report(fa))
    assert badge.color == "red"


def test_build_badge_custom_label():
    fa = FileAudit(path="req.txt", deps=[_dep()])
    badge = build_badge(_report(fa), label="my-project")
    assert badge.label == "my-project"


def test_badge_to_dict_keys():
    fa = FileAudit(path="req.txt", deps=[_dep()])
    d = build_badge(_report(fa)).to_dict()
    assert set(d.keys()) == {"schemaVersion", "label", "message", "color"}
    assert d["schemaVersion"] == 1
