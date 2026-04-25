"""Tests for dep_audit.pruner and dep_audit.cli_pruner."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.pruner import (
    PruneCandidate,
    PruneReport,
    _collect_imports,
    _find_duplicates,
    build_prune_report,
)
from dep_audit.resolver import ResolvedDep


def _dep(name: str, version: str = "1.0.0") -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=version,
        latest_version=version,
        vulns=[],
    )


def _report(*file_audits: FileAudit) -> AuditReport:
    return AuditReport(files=list(file_audits))


# ---------------------------------------------------------------------------
# PruneReport helpers
# ---------------------------------------------------------------------------

def test_prune_report_total():
    pr = PruneReport(candidates=[
        PruneCandidate("requests", "2.31.0", "no_import_found"),
        PruneCandidate("flask", "3.0.0", "duplicate_declaration"),
    ])
    assert pr.total == 2


def test_prune_report_by_reason():
    pr = PruneReport(candidates=[
        PruneCandidate("requests", "2.31.0", "no_import_found"),
        PruneCandidate("flask", "3.0.0", "duplicate_declaration"),
    ])
    assert len(pr.by_reason("no_import_found")) == 1
    assert len(pr.by_reason("duplicate_declaration")) == 1
    assert pr.by_reason("other") == []


# ---------------------------------------------------------------------------
# _collect_imports
# ---------------------------------------------------------------------------

def test_collect_imports_finds_import(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\nimport os\n")
    result = _collect_imports(tmp_path)
    assert "requests" in result
    assert "os" in result


def test_collect_imports_finds_from_import(tmp_path: Path):
    (tmp_path / "app.py").write_text("from flask import Flask\n")
    result = _collect_imports(tmp_path)
    assert "flask" in result


def test_collect_imports_ignores_syntax_errors(tmp_path: Path):
    (tmp_path / "bad.py").write_text("def broken(\n")
    # Should not raise
    result = _collect_imports(tmp_path)
    assert isinstance(result, set)


def test_collect_imports_empty_dir(tmp_path: Path):
    assert _collect_imports(tmp_path) == set()


# ---------------------------------------------------------------------------
# _find_duplicates
# ---------------------------------------------------------------------------

def test_find_duplicates_detects_duplicate():
    fa1 = FileAudit(path="req.txt", deps=[_dep("requests")])
    fa2 = FileAudit(path="dev.txt", deps=[_dep("requests")])
    report = _report(fa1, fa2)
    dupes = _find_duplicates(report)
    assert "requests" in dupes


def test_find_duplicates_no_duplicate():
    fa1 = FileAudit(path="req.txt", deps=[_dep("requests")])
    fa2 = FileAudit(path="dev.txt", deps=[_dep("flask")])
    report = _report(fa1, fa2)
    assert _find_duplicates(report) == set()


# ---------------------------------------------------------------------------
# build_prune_report
# ---------------------------------------------------------------------------

def test_build_prune_report_no_import_found(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\n")
    fa = FileAudit(path="req.txt", deps=[_dep("requests")])
    report = _report(fa)
    pr = build_prune_report(report, source_root=tmp_path)
    assert any(c.name == "requests" and c.reason == "no_import_found" for c in pr.candidates)


def test_build_prune_report_used_dep_not_flagged(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\n")
    fa = FileAudit(path="req.txt", deps=[_dep("requests")])
    report = _report(fa)
    pr = build_prune_report(report, source_root=tmp_path)
    assert pr.total == 0


def test_build_prune_report_duplicate_flagged(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\n")
    fa1 = FileAudit(path="req.txt", deps=[_dep("requests")])
    fa2 = FileAudit(path="dev.txt", deps=[_dep("requests")])
    report = _report(fa1, fa2)
    pr = build_prune_report(report, source_root=tmp_path)
    dupes = pr.by_reason("duplicate_declaration")
    assert any(c.name == "requests" for c in dupes)


# ---------------------------------------------------------------------------
# cli_pruner rendering
# ---------------------------------------------------------------------------

def test_maybe_render_pruner_skips_when_flag_false(tmp_path: Path):
    from dep_audit.cli_pruner import maybe_render_pruner
    args = MagicMock(prune=False)
    printed = []
    maybe_render_pruner(args, _report(), print_fn=printed.append)
    assert printed == []


def test_maybe_render_pruner_text_output(tmp_path: Path):
    from dep_audit.cli_pruner import maybe_render_pruner
    (tmp_path / "app.py").write_text("import os\n")
    fa = FileAudit(path="req.txt", deps=[_dep("requests")])
    report = _report(fa)
    args = MagicMock(prune=True, prune_source_root=str(tmp_path), prune_format="text")
    printed = []
    maybe_render_pruner(args, report, print_fn=printed.append)
    assert printed
    assert "requests" in printed[0]


def test_maybe_render_pruner_json_output(tmp_path: Path):
    import json as _json
    from dep_audit.cli_pruner import maybe_render_pruner
    (tmp_path / "app.py").write_text("import os\n")
    fa = FileAudit(path="req.txt", deps=[_dep("requests")])
    report = _report(fa)
    args = MagicMock(prune=True, prune_source_root=str(tmp_path), prune_format="json")
    printed = []
    maybe_render_pruner(args, report, print_fn=printed.append)
    data = _json.loads(printed[0])
    assert "candidates" in data
    assert data["total"] >= 1
