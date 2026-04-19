"""Tests for dep_audit.cli_tag."""
import argparse
import json

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_tag import add_tag_args, apply_tag_filter, maybe_print_tags


def _dep(name: str) -> ResolvedDep:
    return ResolvedDep(name=name, current_version="1.0", latest_version="2.0", vulns=[])


def _report() -> AuditReport:
    return AuditReport(files=[
        FileAudit(path="req.txt", deps=[_dep("requests"), _dep("flask")]),
    ])


def _parse(extra: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_tag_args(parser)
    return parser.parse_args(extra or [])


def test_defaults():
    args = _parse()
    assert args.tag_file == ".dep_tags.json"
    assert args.filter_tag is None
    assert args.list_tags is False


def test_filter_tag_flag():
    args = _parse(["--filter-tag", "http"])
    assert args.filter_tag == "http"


def test_list_tags_flag():
    args = _parse(["--list-tags"])
    assert args.list_tags is True


def test_custom_tag_file():
    args = _parse(["--tag-file", "custom_tags.json"])
    assert args.tag_file == "custom_tags.json"


def test_apply_tag_filter_no_flag_returns_same_report():
    args = _parse()
    report = _report()
    result = apply_tag_filter(report, args)
    assert result is report


def test_apply_tag_filter_filters_deps(tmp_path):
    tag_file = tmp_path / "tags.json"
    tag_file.write_text(json.dumps({"requests": ["http"]}))
    args = _parse(["--filter-tag", "http", "--tag-file", str(tag_file)])
    result = apply_tag_filter(_report(), args)
    all_names = [d.name for fa in result.files for d in fa.deps]
    assert all_names == ["requests"]


def test_maybe_print_tags_returns_false_when_not_requested():
    args = _parse()
    assert maybe_print_tags(_report(), args) is False


def test_maybe_print_tags_returns_true_and_prints(tmp_path, capsys):
    tag_file = tmp_path / "tags.json"
    tag_file.write_text(json.dumps({"requests": ["http"], "flask": ["web"]}))
    args = _parse(["--list-tags", "--tag-file", str(tag_file)])
    result = maybe_print_tags(_report(), args)
    assert result is True
    out = capsys.readouterr().out
    assert "http" in out
    assert "web" in out


def test_maybe_print_tags_no_tags_message(tmp_path, capsys):
    tag_file = tmp_path / "tags.json"  # does not exist
    args = _parse(["--list-tags", "--tag-file", str(tag_file)])
    maybe_print_tags(_report(), args)
    out = capsys.readouterr().out
    assert "No tags" in out
