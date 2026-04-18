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


# ---------------------------------------------------------------------------
# audit_project integration
# ---------------------------------------------------------------------------

def test_audit_project_calls_finder_and_resolver(tmp_path)_files = [tmp_path / "requirements.txt", tmp_path / "requirements-dev.txt"]
    fake_deps = [_make_dep("requests", "2.28.0", "2.31.0", True)]

    with patch("dep_audit.auditor.find_dependency_files", return_value=fake_files) as mock_find, \
         patch("dep_audit.auditor.resolve_dependencies", return_value=fake_deps) as mock_resolve:

        report = audit_project(tmp_path)

    mock_find.assert_called_once_with(tmp_path)
    assert mock_resolve.call_count == 2
    assert len(report.file_audits) == 2
    assert report.total_outdated == 2


def test_audit_project_empty_project(tmp_path):
    with patch("dep_audit.auditor.find_dependency_files", return_value=[]):
        report = audit_project(tmp_path)

    assert report.total_deps == 0
    assert report.file_audits == []
