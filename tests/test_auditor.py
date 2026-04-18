"""Tests for dep_audit.auditor."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit, audit_project
from dep_audit.resolver import ResolvedDep


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dep(name: str, current: str, latest: str | None, outdated: bool) -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, outdated=outdated)


# ---------------------------------------------------------------------------
# FileAudit
# ---------------------------------------------------------------------------

class TestFileAudit:
    def test_outdated_filters_correctly(self):
        deps = [
            _make_dep("requests", "2.28.0", "2.31.0", True),
            _make_dep("flask", "3.0.0", "3.0.0", False),
        ]
        fa = FileAudit(path=Path("requirements.txt"), dependencies=deps)
        assert len(fa.outdated) == 1
        assert fa.outdated[0].name == "requests"

    def test_has_issues_true_when_outdated(self):
        fa = FileAudit(
            path=Path("requirements.txt"),
            dependencies=[_make_dep("old-pkg", "1.0", "2.0", True)],
        )
        assert fa.has_issues is True

    def test_has_issues_false_when_all_current(self):
        fa = FileAudit(
            path=Path("requirements.txt"),
            dependencies=[_make_dep("up-to-date", "1.0", "1.0", False)],
        )
        assert fa.has_issues is False

    def test_has_issues_false_when_no_dependencies(self):
        """An empty dependency list should not be flagged as having issues."""
        fa = FileAudit(path=Path("requirements.txt"), dependencies=[])
        assert fa.has_issues is False

    def test_outdated_empty_when_no_dependencies(self):
        """outdated should be an empty list when there are no dependencies."""
        fa = FileAudit(path=Path("requirements.txt"), dependencies=[])
        assert fa.outdated == []


# ---------------------------------------------------------------------------
# AuditReport
# ---------------------------------------------------------------------------

class TestAuditReport:
    def _build_report(self) -> AuditReport:
        report = AuditReport(root=Path("/proj"))
        report.file_audits = [
            FileAudit(
                path=Path("/proj/requirements.txt"),
                dependencies=[
                    _make_dep("requests", "2.28.0", "2.31.0", True),
                    _make_dep("flask", "3.0.0", "3.0.0", False),
                ],
            ),
            FileAudit(
                path=Path("/proj/requirements-dev.txt"),
                dependencies=[
                    _make_dep("pytest", "7.0.0", "7.0.0", False),
                ],
            ),
        ]
        return report

    def test_total_deps(self):
        assert self._build_report().total_deps == 3

    def test_total_outdated(self):
        assert self._build_report().total_outdated == 1

    def test_files_with_issues(self):
        report = self._build_report()
        assert len(report.files_with_issues) == 1
        assert report.files_with_issues[0].path.name == "requirements.txt"

    def test_total_deps_empty_report(self):
        """total_deps should be zero when no file audits have been added."""
        report = AuditReport(root=Path("/proj"))
        assert report.total_deps == 0

    def test_total_outdated_empty_report(self):
        """total_outdated should be zero when no file audits have been added."""
        report = AuditReport(root=Path("/proj"))
        assert report.total_outdated == 0


# ---------------------------------------------------------------------------
# audit_project integration
# --------------------------------------------------------------
