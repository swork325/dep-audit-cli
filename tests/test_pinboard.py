"""Tests for dep_audit.pinboard."""
from __future__ import annotations

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.pinboard import (
    PinboardReport,
    PinStatus,
    _is_pinned,
    _build_pin_status,
    build_pinboard,
)
from dep_audit.resolver import ResolvedDep


def _dep(
    name: str,
    current: str | None = "1.0.0",
    latest: str | None = "1.0.0",
    outdated: bool = False,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=outdated,
        vulnerabilities=[],
    )


def _report(*file_tuples) -> AuditReport:
    files = [
        FileAudit(path=path, deps=list(deps))
        for path, deps in file_tuples
    ]
    return AuditReport(files=files)


# --- _is_pinned ---

def test_is_pinned_exact_equals():
    assert _is_pinned("==1.2.3") is True


def test_is_pinned_bare_version():
    assert _is_pinned("1.2.3") is True


def test_is_pinned_range_returns_false():
    assert _is_pinned(">=1.0") is False


def test_is_pinned_none_returns_false():
    assert _is_pinned(None) is False


def test_is_pinned_empty_returns_false():
    assert _is_pinned("") is False


# --- _build_pin_status ---

def test_build_pin_status_pinned():
    dep = _dep("requests", current="==2.28.0", latest="2.31.0", outdated=True)
    status = _build_pin_status(dep)
    assert status.is_pinned is True
    assert status.is_outdated is True
    assert status.suggested_pin == "==2.31.0"


def test_build_pin_status_unpinned():
    dep = _dep("flask", current=">=2.0", latest="3.0.0")
    status = _build_pin_status(dep)
    assert status.is_pinned is False
    assert status.suggested_pin == "==3.0.0"


def test_build_pin_status_no_latest():
    dep = _dep("mylib", current=">=1.0", latest=None)
    status = _build_pin_status(dep)
    assert status.suggested_pin is None


# --- build_pinboard ---

def test_build_pinboard_separates_pinned_and_unpinned():
    report = _report(
        ("req.txt", [_dep("requests", current="==2.28.0"), _dep("flask", current=">=2.0")]),
    )
    pb = build_pinboard(report)
    assert len(pb.pinned) == 1
    assert len(pb.unpinned) == 1
    assert pb.pinned[0].name == "requests"
    assert pb.unpinned[0].name == "flask"


def test_build_pinboard_deduplicates_across_files():
    dep = _dep("requests", current="==2.28.0")
    report = _report(
        ("a/req.txt", [dep]),
        ("b/req.txt", [dep]),
    )
    pb = build_pinboard(report)
    assert pb.total == 1


def test_build_pinboard_pin_rate():
    report = _report(
        ("req.txt", [
            _dep("a", current="==1.0"),
            _dep("b", current=">=1.0"),
            _dep("c", current=">=2.0"),
        ]),
    )
    pb = build_pinboard(report)
    assert pb.pin_rate == pytest.approx(1 / 3)


def test_build_pinboard_empty_report():
    report = _report()
    pb = build_pinboard(report)
    assert pb.total == 0
    assert pb.pin_rate == 0.0


import pytest  # noqa: E402  (kept at bottom to mirror project style)
