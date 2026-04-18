"""Tests for dep_audit.sorter and dep_audit.cli_sort."""
import argparse
import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import FileAudit, AuditReport
from dep_audit.vulnerability import Vulnerability, VulnResult
from dep_audit.sorter import SortConfig, sort_report
from dep_audit.cli_sort import add_sort_args, sort_config_from_args


def _dep(name, outdated=False, severity=None):
    vulns = []
    if severity:
        vulns = [Vulnerability(vuln_id="CVE-x", description="", severity=severity)]
    return ResolvedDep(
        name=name,
        current_version="1.0.0",
        latest_version="2.0.0" if outdated else "1.0.0",
        is_outdated=outdated,
        vulns=vulns,
    )


@pytest.fixture
def report():
    fa1 = FileAudit(path="b/req.txt", deps=[_dep("zlib"), _dep("requests", outdated=True)])
    fa2 = FileAudit(path="a/req.txt", deps=[_dep("flask", severity="high"), _dep("boto3")])
    return AuditReport(files=[fa1, fa2])


def test_sort_by_name(report):
    result = sort_report(report, SortConfig(key="name"))
    for fa in result.files:
        names = [d.name for d in fa.deps]
        assert names == sorted(names, key=str.lower)


def test_sort_by_name_reverse(report):
    result = sort_report(report, SortConfig(key="name", reverse=True))
    for fa in result.files:
        names = [d.name for d in fa.deps]
        assert names == sorted(names, key=str.lower, reverse=True)


def test_sort_by_outdated_puts_outdated_first(report):
    result = sort_report(report, SortConfig(key="outdated"))
    fa = next(f for f in result.files if "b/" in str(f.path))
    assert fa.deps[0].is_outdated


def test_sort_by_severity_puts_high_first(report):
    result = sort_report(report, SortConfig(key="severity"))
    fa = next(f for f in result.files if "a/" in str(f.path))
    assert fa.deps[0].name == "flask"


def test_sort_by_file_orders_files(report):
    result = sort_report(report, SortConfig(key="file"))
    paths = [str(f.path) for f in result.files]
    assert paths == sorted(paths, key=str.lower)


def _parse(args):
    parser = argparse.ArgumentParser()
    add_sort_args(parser)
    return parser.parse_args(args)


def test_cli_sort_defaults():
    ns = _parse([])
    assert ns.sort_by is None
    assert ns.sort_desc is False


def test_cli_sort_config_none_when_no_key():
    ns = _parse([])
    assert sort_config_from_args(ns) is None


def test_cli_sort_config_returns_config():
    ns = _parse(["--sort-by", "severity", "--sort-desc"])
    cfg = sort_config_from_args(ns)
    assert cfg is not None
    assert cfg.key == "severity"
    assert cfg.reverse is True
