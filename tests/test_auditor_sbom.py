"""Tests for dep_audit.auditor_sbom and dep_audit.cli_sbom."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.auditor_sbom import SBOMComponent, SBOMDocument, build_sbom, save_sbom
from dep_audit.cli_sbom import add_sbom_args, maybe_render_sbom
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability, VulnResult


def _dep(
    name="requests",
    version="2.27.0",
    latest="2.31.0",
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        version=version,
        latest=latest,
        vulns=vulns or [],
    )


def _report(*file_deps: tuple) -> AuditReport:
    files = [
        FileAudit(path=path, deps=list(deps))
        for path, deps in file_deps
    ]
    return AuditReport(files=files)


# ---------------------------------------------------------------------------
# SBOMDocument
# ---------------------------------------------------------------------------

def test_sbom_document_total():
    doc = SBOMDocument(components=[SBOMComponent("a", "1.0", "req.txt", False, False)])
    assert doc.total == 1


def test_sbom_document_to_dict_keys():
    doc = SBOMDocument()
    d = doc.to_dict()
    assert d["bomFormat"] == "CycloneDX"
    assert d["specVersion"] == "1.4"
    assert "serialNumber" in d
    assert "metadata" in d
    assert "components" in d


def test_sbom_component_to_dict_flags():
    comp = SBOMComponent("flask", "2.0.0", "req.txt", is_outdated=True, is_vulnerable=False)
    d = comp.to_dict()
    props = {p["name"]: p["value"] for p in d["properties"]}
    assert props["dep-audit:outdated"] == "true"
    assert props["dep-audit:vulnerable"] == "false"


# ---------------------------------------------------------------------------
# build_sbom
# ---------------------------------------------------------------------------

def test_build_sbom_includes_all_deps():
    report = _report(
        ("req.txt", [_dep("requests"), _dep("flask", version="2.0.0", latest="2.0.0")]),
    )
    doc = build_sbom(report)
    names = {c.name for c in doc.components}
    assert "requests" in names
    assert "flask" in names


def test_build_sbom_deduplicates_same_dep():
    dep = _dep("requests", version="2.27.0", latest="2.31.0")
    report = _report(
        ("req.txt", [dep]),
        ("req-dev.txt", [dep]),
    )
    doc = build_sbom(report)
    assert doc.total == 1


def test_build_sbom_marks_outdated():
    report = _report(("req.txt", [_dep("requests", version="2.27.0", latest="2.31.0")]))
    doc = build_sbom(report)
    assert doc.components[0].is_outdated is True


def test_build_sbom_marks_not_outdated_when_current():
    report = _report(("req.txt", [_dep("flask", version="2.0.0", latest="2.0.0")]))
    doc = build_sbom(report)
    assert doc.components[0].is_outdated is False


# ---------------------------------------------------------------------------
# save_sbom
# ---------------------------------------------------------------------------

def test_save_sbom_creates_file(tmp_path):
    doc = SBOMDocument()
    dest = str(tmp_path / "sbom.json")
    save_sbom(doc, dest)
    assert Path(dest).exists()


def test_save_sbom_valid_json(tmp_path):
    report = _report(("req.txt", [_dep()]))
    doc = build_sbom(report)
    dest = str(tmp_path / "sbom.json")
    save_sbom(doc, dest)
    data = json.loads(Path(dest).read_text())
    assert data["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse(*argv):
    parser = argparse.ArgumentParser()
    add_sbom_args(parser)
    return parser.parse_args(list(argv))


def test_defaults():
    args = _parse()
    assert args.sbom is False
    assert args.sbom_output is None
    assert args.sbom_format == "json"


def test_sbom_flag():
    args = _parse("--sbom")
    assert args.sbom is True


def test_maybe_render_sbom_skipped_when_flag_absent():
    report = _report(("req.txt", [_dep()]))
    args = _parse()
    result = maybe_render_sbom(args, report)
    assert result is None


def test_maybe_render_sbom_returns_zero(capsys):
    report = _report(("req.txt", [_dep()]))
    args = _parse("--sbom")
    result = maybe_render_sbom(args, report)
    assert result == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["bomFormat"] == "CycloneDX"


def test_maybe_render_sbom_text_format(capsys):
    report = _report(("req.txt", [_dep()]))
    args = _parse("--sbom", "--sbom-format", "text")
    maybe_render_sbom(args, report)
    captured = capsys.readouterr()
    assert "SBOM" in captured.out
    assert "requests" in captured.out


def test_maybe_render_sbom_writes_file(tmp_path):
    report = _report(("req.txt", [_dep()]))
    dest = str(tmp_path / "out.json")
    args = _parse("--sbom", "--sbom-output", dest)
    maybe_render_sbom(args, report)
    assert Path(dest).exists()
    data = json.loads(Path(dest).read_text())
    assert "components" in data
