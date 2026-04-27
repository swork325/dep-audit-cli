"""Tests for dep_audit.exemptions and dep_audit.cli_exemptions."""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from dep_audit.exemptions import (
    Exemption,
    load_exemptions,
    save_exemptions,
    active_exemptions,
    apply_exemptions,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit


_FUTURE = datetime.now(timezone.utc) + timedelta(days=30)
_PAST = datetime.now(timezone.utc) - timedelta(days=1)


def _dep(name: str, latest: str = "2.0.0", installed: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, installed=installed, latest=latest, vulns=[])


def _report(*names: str) -> AuditReport:
    fa = FileAudit(path="requirements.txt", deps=[_dep(n) for n in names])
    return AuditReport(files=[fa])


# --- Exemption dataclass ---

def test_exemption_is_expired_when_past():
    e = Exemption(package="flask", reason="ok", expires=_PAST)
    assert e.is_expired()


def test_exemption_not_expired_when_future():
    e = Exemption(package="flask", reason="ok", expires=_FUTURE)
    assert not e.is_expired()


def test_exemption_to_dict_roundtrip():
    e = Exemption(package="requests", reason="audit pending", expires=_FUTURE, added_by="ci")
    restored = Exemption.from_dict(e.to_dict())
    assert restored.package == "requests"
    assert restored.reason == "audit pending"
    assert restored.added_by == "ci"


def test_from_dict_lowercases_package():
    d = {"package": "Requests", "reason": "x", "expires": _FUTURE.isoformat(), "added_by": "me"}
    e = Exemption.from_dict(d)
    assert e.package == "requests"


# --- load / save ---

def test_load_returns_empty_when_missing(tmp_path):
    result = load_exemptions(str(tmp_path / "no.json"))
    assert result == []


def test_load_returns_empty_on_invalid_json(tmp_path):
    f = tmp_path / "ex.json"
    f.write_text("not json")
    assert load_exemptions(str(f)) == []


def test_load_returns_empty_on_wrong_type(tmp_path):
    f = tmp_path / "ex.json"
    f.write_text(json.dumps({"package": "x"}))
    assert load_exemptions(str(f)) == []


def test_save_and_reload(tmp_path):
    f = str(tmp_path / "ex.json")
    exemptions = [
        Exemption(package="flask", reason="r", expires=_FUTURE),
        Exemption(package="django", reason="s", expires=_PAST),
    ]
    save_exemptions(exemptions, f)
    loaded = load_exemptions(f)
    assert len(loaded) == 2
    assert loaded[0].package == "flask"


# --- active_exemptions ---

def test_active_exemptions_excludes_expired():
    exemptions = [
        Exemption(package="flask", reason="r", expires=_FUTURE),
        Exemption(package="django", reason="s", expires=_PAST),
    ]
    active = active_exemptions(exemptions)
    assert "flask" in active
    assert "django" not in active


# --- apply_exemptions ---

def test_apply_exemptions_removes_active():
    report = _report("flask", "requests", "django")
    exemptions = [Exemption(package="flask", reason="r", expires=_FUTURE)]
    result = apply_exemptions(report, exemptions)
    names = [d.name for d in result.files[0].deps]
    assert "flask" not in names
    assert "requests" in names


def test_apply_exemptions_keeps_expired():
    report = _report("flask", "requests")
    exemptions = [Exemption(package="flask", reason="r", expires=_PAST)]
    result = apply_exemptions(report, exemptions)
    names = [d.name for d in result.files[0].deps]
    assert "flask" in names


def test_apply_exemptions_empty_list_unchanged():
    report = _report("flask", "requests")
    result = apply_exemptions(report, [])
    assert len(result.files[0].deps) == 2
