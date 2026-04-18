"""Tests for dep_audit.formatter."""
from __future__ import annotations

import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.formatter import render
from dep_audit.resolver import ResolvedDep


def _dep(
    name: str,
    current: str = "1.0.0",
    latest: str = "1.0.0",
    vulns: list[str] | None = None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current=current,
        latest=latest,
        is_outdated=current != latest,
        vulnerabilities=vulns or [],
    )


@pytest.fixture()
def report() -> AuditReport:
    files = [
        FileAudit(
            path="requirements.txt",
            deps=[
                _dep("requests", "2.28.0", "2.31.0"),
                _dep("flask", "2.3.0", "2.3.0"),
            ],
        ),
        FileAudit(
            path="requirements-dev.txt",
            deps=[
                _dep("pytest", "7.0.0", "7.0.0", vulns=["CVE-2023-1234"]),
            ],
        ),
    ]
    return AuditReport(files=files)


def test_text_contains_file_paths(report: AuditReport) -> None:
    output = render(report, fmt="text")
    assert "requirements.txt" in output
    assert "requirements-dev.txt" in output


def test_text_shows_outdated_dep(report: AuditReport) -> None:
    output = render(report, fmt="text")
    assert "2.28.0 → 2.31.0" in output


def test_text_shows_vulnerable_dep(report: AuditReport) -> None:
    output = render(report, fmt="text")
    assert "CVE-2023-1234" in output


def test_text_shows_summary_counts(report: AuditReport) -> None:
    output = render(report, fmt="text")
    assert "3 deps" in output
    assert "1 outdated" in output
    assert "1 vulnerable" in output


def test_json_is_valid_json(report: AuditReport) -> None:
    output = render(report, fmt="json")
    data = json.loads(output)
    assert "summary" in data
    assert "files" in data


def test_json_summary_counts(report: AuditReport) -> None:
    data = json.loads(render(report, fmt="json"))
    assert data["summary"]["total_deps"] == 3
    assert data["summary"]["total_outdated"] == 1
    assert data["summary"]["total_vulnerable"] == 1


def test_json_dep_structure(report: AuditReport) -> None:
    data = json.loads(render(report, fmt="json"))
    dep = data["files"][0]["deps"][0]
    assert dep["name"] == "requests"
    assert dep["is_outdated"] is True
    assert dep["vulnerabilities"] == []


def test_text_ok_label_for_clean_file() -> None:
    clean = AuditReport(files=[FileAudit(path="setup.cfg", deps=[_dep("six")])])
    output = render(clean, fmt="text")
    assert "[OK]" in output
