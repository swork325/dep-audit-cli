"""Tests for dep_audit.attestor and dep_audit.cli_attestor."""
from __future__ import annotations

import argparse
import json
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.attestor import (
    AttestationEntry,
    AttestationReport,
    _sha256_of,
    attest_dep,
    build_attestation_report,
    load_attestation_map,
    save_attestation_map,
)
from dep_audit.cli_attestor import (
    _render_json,
    _render_text,
    add_attestor_args,
    maybe_render_attestation,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, current: str = "1.0.0", latest: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, vulnerabilities=[])


def _report(deps):
    fa = MagicMock()
    fa.deps = deps
    fa.path = "requirements.txt"
    report = MagicMock()
    report.files = [fa]
    return report


def _parse(**kwargs) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_attestor_args(parser)
    args = parser.parse_args([])
    for k, v in kwargs.items():
        setattr(args, k, v)
    return args


# --- attestor unit tests ---

def test_sha256_of_is_deterministic():
    assert _sha256_of("requests==2.31.0") == _sha256_of("requests==2.31.0")


def test_attest_dep_verified_when_in_map():
    dep = _dep("requests", "2.31.0")
    expected = _sha256_of("requests==2.31.0")
    entry = attest_dep(dep, {"requests": expected})
    assert entry.verified is True


def test_attest_dep_mismatch_when_wrong_hash():
    dep = _dep("requests", "2.31.0")
    entry = attest_dep(dep, {"requests": "badhash"})
    assert entry.verified is False


def test_attest_dep_mismatch_when_not_in_map():
    dep = _dep("flask", "3.0.0")
    entry = attest_dep(dep, {})
    assert entry.verified is False


def test_attestation_entry_to_dict_keys():
    entry = AttestationEntry("pkg", "1.0", "abc", "abc")
    d = entry.to_dict()
    assert set(d.keys()) == {"name", "version", "expected_sha256", "actual_sha256", "verified"}


def test_attestation_report_counts():
    e1 = AttestationEntry("a", "1", "x", "x")
    e2 = AttestationEntry("b", "2", "y", "z")
    ar = AttestationReport(entries=[e1, e2])
    assert ar.total == 2
    assert ar.verified_count == 1
    assert ar.failed_count == 1
    assert ar.all_verified is False


def test_load_attestation_map_missing_file(tmp_path):
    result = load_attestation_map(tmp_path / "missing.json")
    assert result == {}


def test_load_attestation_map_invalid_json(tmp_path):
    f = tmp_path / "a.json"
    f.write_text("not json")
    assert load_attestation_map(f) == {}


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "attest.json"
    save_attestation_map(path, {"requests": "abc123"})
    loaded = load_attestation_map(path)
    assert loaded["requests"] == "abc123"


def test_load_normalises_keys_to_lowercase(tmp_path):
    path = tmp_path / "attest.json"
    path.write_text(json.dumps({"Requests": "abc"}))
    loaded = load_attestation_map(path)
    assert "requests" in loaded


def test_build_attestation_report_deduplicates():
    dep = _dep("requests", "2.31.0")
    rep = _report([dep, dep])
    ar = build_attestation_report(rep, {})
    assert ar.total == 1


# --- cli_attestor tests ---

def test_defaults():
    args = _parse()
    assert args.attest is False
    assert args.attest_file == ".dep_attestations.json"
    assert args.attest_format == "text"
    assert args.attest_fail_on_mismatch is False


def test_render_text_contains_header():
    ar = AttestationReport(entries=[AttestationEntry("flask", "3.0", "h", "h")])
    text = _render_text(ar)
    assert "Attestation Report" in text
    assert "flask" in text
    assert "VERIFIED" in text


def test_render_json_structure():
    ar = AttestationReport(entries=[AttestationEntry("flask", "3.0", "h", "h")])
    data = json.loads(_render_json(ar))
    assert "entries" in data
    assert data["verified"] == 1


def test_maybe_render_attestation_skips_when_flag_false():
    args = _parse(attest=False)
    out = StringIO()
    code = maybe_render_attestation(args, _report([]), out=out)
    assert code == 0
    assert out.getvalue() == ""


def test_maybe_render_attestation_returns_zero_all_ok(tmp_path):
    dep = _dep("requests", "2.31.0")
    expected_hash = _sha256_of("requests==2.31.0")
    attest_file = tmp_path / "attest.json"
    save_attestation_map(attest_file, {"requests": expected_hash})
    args = _parse(attest=True, attest_file=str(attest_file), attest_format="text", attest_fail_on_mismatch=True)
    out = StringIO()
    code = maybe_render_attestation(args, _report([dep]), out=out)
    assert code == 0


def test_maybe_render_attestation_returns_two_on_mismatch(tmp_path):
    dep = _dep("requests", "2.31.0")
    attest_file = tmp_path / "attest.json"
    save_attestation_map(attest_file, {"requests": "badhash"})
    args = _parse(attest=True, attest_file=str(attest_file), attest_format="text", attest_fail_on_mismatch=True)
    out = StringIO()
    code = maybe_render_attestation(args, _report([dep]), out=out)
    assert code == 2
