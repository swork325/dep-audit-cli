"""Tests for dep_audit.suppressor."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.suppressor import (
    add_suppression,
    apply_suppressions,
    is_suppressed,
    load_suppressions,
    remove_suppression,
    save_suppressions,
)


def _dep(name: str, current: str = "1.0.0", latest: str | None = None) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest or current,
        vulns=[],
    )


_FUTURE = (date.today() + timedelta(days=30)).isoformat()
_PAST = (date.today() - timedelta(days=1)).isoformat()


def test_load_returns_empty_when_file_missing(tmp_path: Path) -> None:
    result = load_suppressions(tmp_path / "nope.json")
    assert result == {}


def test_load_returns_empty_on_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    p.write_text("not json")
    assert load_suppressions(p) == {}


def test_load_returns_empty_on_wrong_type(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    p.write_text(json.dumps(["requests"]))
    assert load_suppressions(p) == {}


def test_load_normalises_keys_to_lowercase(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"Requests": _FUTURE}))
    result = load_suppressions(p)
    assert "requests" in result


def test_save_and_reload(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    save_suppressions({"flask": _FUTURE}, p)
    result = load_suppressions(p)
    assert result == {"flask": _FUTURE}


def test_is_suppressed_returns_true_for_future_expiry() -> None:
    dep = _dep("requests")
    assert is_suppressed(dep, {"requests": _FUTURE}) is True


def test_is_suppressed_returns_false_for_past_expiry() -> None:
    dep = _dep("requests")
    assert is_suppressed(dep, {"requests": _PAST}) is False


def test_is_suppressed_returns_false_when_not_in_map() -> None:
    dep = _dep("flask")
    assert is_suppressed(dep, {"requests": _FUTURE}) is False


def test_is_suppressed_returns_false_on_bad_date() -> None:
    dep = _dep("requests")
    assert is_suppressed(dep, {"requests": "not-a-date"}) is False


def test_apply_suppressions_removes_suppressed_dep() -> None:
    deps = [_dep("requests"), _dep("flask")]
    fa = FileAudit(path=Path("requirements.txt"), deps=deps)
    report = AuditReport(files=[fa])
    result = apply_suppressions(report, {"requests": _FUTURE})
    names = [d.name for d in result.files[0].deps]
    assert "requests" not in names
    assert "flask" in names


def test_apply_suppressions_keeps_expired_suppression() -> None:
    deps = [_dep("requests")]
    fa = FileAudit(path=Path("requirements.txt"), deps=deps)
    report = AuditReport(files=[fa])
    result = apply_suppressions(report, {"requests": _PAST})
    assert len(result.files[0].deps) == 1


def test_add_suppression_creates_entry(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    expiry = date.today() + timedelta(days=7)
    add_suppression("django", expiry, path=p)
    data = load_suppressions(p)
    assert data.get("django") == expiry.isoformat()


def test_remove_suppression_returns_true_when_exists(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    save_suppressions({"django": _FUTURE}, p)
    assert remove_suppression("django", path=p) is True
    assert "django" not in load_suppressions(p)


def test_remove_suppression_returns_false_when_missing(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    assert remove_suppression("django", path=p) is False
