"""Tests for dep_audit.exporter."""
import json
import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.exporter import export, export_csv, export_json


def _dep(name, current="1.0.0", latest="2.0.0", outdated=True, vulns=None):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=outdated,
        vulnerabilities=vulns or [],
    )


@pytest.fixture()
def report():
    deps = [
        _dep("requests", vulns=[Vulnerability(vuln_id="PYSEC-1", description="RCE bug")]),
        _dep("flask", current="2.0.0", latest="2.0.0", outdated=False),
    ]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


def test_export_json_structure(report):
    result = json.loads(export_json(report))
    assert "files" in result
    assert result["files"][0]["path"] == "requirements.txt"


def test_export_json_dep_fields(report):
    result = json.loads(export_json(report))
    dep = result["files"][0]["dependencies"][0]
    assert dep["name"] == "requests"
    assert dep["is_outdated"] is True
    assert dep["vulnerabilities"][0]["id"] == "PYSEC-1"


def test_export_csv_header(report):
    csv_text = export_csv(report)
    first_line = csv_text.splitlines()[0]
    assert "package" in first_line
    assert "vuln_ids" in first_line


def test_export_csv_rows(report):
    csv_text = export_csv(report)
    lines = csv_text.strip().splitlines()
    # header + 2 deps
    assert len(lines) == 3


def test_export_csv_vuln_ids(report):
    csv_text = export_csv(report)
    assert "PYSEC-1" in csv_text


def test_export_dispatches_json(report):
    result = export(report, "json")
    parsed = json.loads(result)
    assert "files" in parsed


def test_export_dispatches_csv(report):
    result = export(report, "csv")
    assert "package" in result


def test_export_unknown_format_raises(report):
    with pytest.raises(ValueError, match="Unsupported export format"):
        export(report, "xml")
