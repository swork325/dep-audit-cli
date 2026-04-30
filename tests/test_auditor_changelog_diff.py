"""Tests for dep_audit.auditor_changelog_diff."""
from __future__ import annotations

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor_changelog_diff import (
    build_changelog_diff,
    VersionChange,
    ChangelogDiffReport,
)


def _dep(
    name: str,
    current: str = "1.0.0",
    latest: str = "1.0.0",
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulnerabilities=vulns or [],
    )


def _report(*deps: ResolvedDep) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


# ---------------------------------------------------------------------------
# VersionChange helpers
# ---------------------------------------------------------------------------

def test_version_change_to_dict_keys():
    vc = VersionChange("requests", "2.28.0", "2.31.0", False, True)
    d = vc.to_dict()
    assert set(d) == {"name", "old_version", "new_version", "was_outdated", "is_outdated", "upgraded", "downgraded"}


def test_version_change_upgraded_true():
    vc = VersionChange("flask", "2.0.0", "3.0.0", True, False)
    assert vc._upgraded() is True
    assert vc._downgraded() is False


def test_version_change_same_version_not_upgraded():
    vc = VersionChange("flask", "2.0.0", "2.0.0", False, False)
    assert vc._upgraded() is False


def test_version_change_none_old_not_upgraded():
    vc = VersionChange("flask", None, "2.0.0", False, False)
    assert vc._upgraded() is False


# ---------------------------------------------------------------------------
# build_changelog_diff
# ---------------------------------------------------------------------------

def test_no_version_changes_returns_empty_report():
    old = _report(_dep("requests", "2.28.0", "2.31.0"))
    new = _report(_dep("requests", "2.28.0", "2.31.0"))
    result = build_changelog_diff(old, new)
    assert result.total == 0


def test_detects_version_upgrade():
    old = _report(_dep("requests", "2.28.0"))
    new = _report(_dep("requests", "2.31.0"))
    result = build_changelog_diff(old, new)
    assert result.total == 1
    assert result.changes[0].name == "requests"
    assert result.changes[0].old_version == "2.28.0"
    assert result.changes[0].new_version == "2.31.0"


def test_detects_newly_added_package():
    old = _report(_dep("flask", "2.0.0"))
    new = _report(_dep("flask", "2.0.0"), _dep("click", "8.0.0"))
    result = build_changelog_diff(old, new)
    assert result.total == 1
    change = result.changes[0]
    assert change.name == "click"
    assert change.old_version is None
    assert change.new_version == "8.0.0"


def test_detects_removed_package():
    old = _report(_dep("flask", "2.0.0"), _dep("click", "8.0.0"))
    new = _report(_dep("flask", "2.0.0"))
    result = build_changelog_diff(old, new)
    assert result.total == 1
    assert result.changes[0].name == "click"
    assert result.changes[0].new_version is None


def test_newly_outdated_property():
    old = _report(_dep("requests", "2.28.0", "2.28.0"))  # was current
    new = _report(_dep("requests", "2.28.0", "2.31.0"))  # now outdated, version unchanged
    # version unchanged so no diff expected — supply explicit outdated flag via different version
    old2 = _report(_dep("requests", "2.27.0", "2.27.0"))
    new2 = _report(_dep("requests", "2.28.0", "2.31.0"))
    result = build_changelog_diff(old2, new2)
    assert result.total == 1
    assert result.changes[0].is_outdated is True


def test_upgraded_list_populated():
    old = _report(_dep("flask", "2.0.0"), _dep("click", "7.0.0"))
    new = _report(_dep("flask", "3.0.0"), _dep("click", "8.0.0"))
    result = build_changelog_diff(old, new)
    assert len(result.upgraded) == 2
