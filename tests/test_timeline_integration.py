"""Integration tests: timeline update across multiple consecutive runs."""
from __future__ import annotations

from pathlib import Path

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.timeline import load_timeline, update_timeline
from dep_audit.vulnerability import Vulnerability


def _dep(name: str, version: str = "1.0.0", latest: str | None = None, vulns=None):
    return ResolvedDep(name=name, version=version, latest=latest, vulns=vulns or [])


def _report(*deps):
    fa = FileAudit(path="requirements.txt", deps=list(deps))
    return AuditReport(files=[fa])


def test_multiple_runs_accumulate_seen_count(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("requests", "2.28.0"))
    for _ in range(5):
        update_timeline(report, p)
    tl = load_timeline(p)
    assert tl.entries["requests"].seen_count == 5


def test_outdated_flag_becomes_true_after_later_run(tmp_path):
    p = tmp_path / "tl.json"
    run1 = _report(_dep("flask", "3.0.0"))
    update_timeline(run1, p)
    assert load_timeline(p).entries["flask"].was_outdated is False

    run2 = _report(_dep("flask", "3.0.0", latest="3.1.0"))
    update_timeline(run2, p)
    assert load_timeline(p).entries["flask"].was_outdated is True


def test_vulnerable_flag_becomes_true_after_later_run(tmp_path):
    p = tmp_path / "tl.json"
    run1 = _report(_dep("django", "4.2.0"))
    update_timeline(run1, p)

    vuln = Vulnerability(id="CVE-2024-99", description="rce", severity="critical", fixed_in="4.2.1")
    run2 = _report(_dep("django", "4.2.0", vulns=[vuln]))
    update_timeline(run2, p)

    tl = load_timeline(p)
    assert tl.entries["django"].was_vulnerable is True


def test_new_package_added_in_later_run(tmp_path):
    p = tmp_path / "tl.json"
    update_timeline(_report(_dep("flask")), p)
    update_timeline(_report(_dep("flask"), _dep("celery")), p)
    tl = load_timeline(p)
    assert "celery" in tl.entries
    assert tl.entries["celery"].seen_count == 1
    assert tl.entries["flask"].seen_count == 2


def test_first_seen_is_preserved_across_runs(tmp_path):
    p = tmp_path / "tl.json"
    update_timeline(_report(_dep("boto3")), p)
    first = load_timeline(p).entries["boto3"].first_seen
    update_timeline(_report(_dep("boto3")), p)
    assert load_timeline(p).entries["boto3"].first_seen == first


def test_total_reflects_unique_packages(tmp_path):
    p = tmp_path / "tl.json"
    report = _report(_dep("a"), _dep("b"), _dep("c"))
    tl = update_timeline(report, p)
    assert tl.total() == 3
