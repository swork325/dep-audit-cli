"""Tests for dep_audit.cli_supply_chain."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.auditor_supply_chain import SupplyChainEntry, SupplyChainReport
from dep_audit.cli_supply_chain import (
    add_supply_chain_args,
    _render_text,
    _render_json,
    maybe_render_supply_chain,
)


def _dep(name: str, current: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=current, vulns=[])


def _report(*pairs) -> AuditReport:
    files = [FileAudit(path=p, deps=list(deps)) for p, deps in pairs]
    return AuditReport(files=files)


def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_supply_chain_args(parser)
    return parser.parse_args(list(args))


# ── argument defaults ─────────────────────────────────────────────────────────

def test_defaults():
    ns = _parse()
    assert ns.supply_chain is False
    assert ns.supply_chain_format == "text"
    assert ns.supply_chain_suspicious_only is False


def test_supply_chain_flag():
    ns = _parse("--supply-chain")
    assert ns.supply_chain is True


def test_supply_chain_format_json():
    ns = _parse("--supply-chain-format", "json")
    assert ns.supply_chain_format == "json"


def test_supply_chain_suspicious_only_flag():
    ns = _parse("--supply-chain-suspicious-only")
    assert ns.supply_chain_suspicious_only is True


# ── _render_text ──────────────────────────────────────────────────────────────

def test_render_text_no_issues():
    sc = SupplyChainReport(entries=[
        SupplyChainEntry(package="requests", version="2.28.0"),
    ])
    out = _render_text(sc, suspicious_only=False)
    assert "requests" in out
    assert "No supply-chain issues" not in out


def test_render_text_suspicious_only_hides_clean():
    sc = SupplyChainReport(entries=[
        SupplyChainEntry(package="requests", version="2.28.0"),
        SupplyChainEntry(package="requsets", version="1.0", suspicious=True, typosquat_of="requests"),
    ])
    out = _render_text(sc, suspicious_only=True)
    assert "requsets" in out
    # clean package should not appear in suspicious-only view
    lines = [l for l in out.splitlines() if "requests" in l and "requsets" not in l and "similar" not in l]
    assert len(lines) == 0 or all("Total" in l or "=" in l for l in lines)


def test_render_text_shows_suspicious_label():
    sc = SupplyChainReport(entries=[
        SupplyChainEntry(package="requsets", version="1.0", suspicious=True, typosquat_of="requests"),
    ])
    out = _render_text(sc, suspicious_only=False)
    assert "SUSPICIOUS" in out
    assert "requests" in out


# ── _render_json ──────────────────────────────────────────────────────────────

def test_render_json_structure():
    sc = SupplyChainReport(entries=[
        SupplyChainEntry(package="requsets", version="1.0", suspicious=True, typosquat_of="requests"),
    ])
    data = json.loads(_render_json(sc, suspicious_only=False))
    assert "total" in data
    assert "suspicious_count" in data
    assert "entries" in data


def test_render_json_suspicious_only_filters():
    sc = SupplyChainReport(entries=[
        SupplyChainEntry(package="requests", version="2.28.0"),
        SupplyChainEntry(package="requsets", version="1.0", suspicious=True, typosquat_of="requests"),
    ])
    data = json.loads(_render_json(sc, suspicious_only=True))
    assert len(data["entries"]) == 1
    assert data["entries"][0]["package"] == "requsets"


# ── maybe_render_supply_chain ─────────────────────────────────────────────────

def test_maybe_render_supply_chain_skips_when_flag_off():
    ns = _parse()
    report = _report(("req.txt", [_dep("requests")]))
    captured = []
    result = maybe_render_supply_chain(ns, report, print_fn=captured.append)
    assert result is None
    assert captured == []


def test_maybe_render_supply_chain_renders_when_flag_on():
    ns = _parse("--supply-chain")
    report = _report(("req.txt", [_dep("requests")]))
    captured = []
    result = maybe_render_supply_chain(ns, report, print_fn=captured.append)
    assert result is not None
    assert len(captured) == 1
