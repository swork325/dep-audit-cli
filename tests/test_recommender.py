"""Tests for dep_audit.recommender."""
import pytest
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability
from dep_audit.recommender import (
    recommend_for_dep,
    build_recommendations,
    Recommendation,
)
from dep_audit.auditor import AuditReport, FileAudit


def _dep(name, current, latest, vulns=None):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulns=vulns or [],
    )


def _vuln(vid="VULN-1", severity="high"):
    return Vulnerability(vuln_id=vid, description="desc", severity=severity, fix_versions=[])


def test_recommend_for_dep_clean_returns_none():
    dep = _dep("requests", "2.28.0", "2.28.0")
    assert recommend_for_dep(dep) is None


def test_recommend_for_dep_outdated():
    dep = _dep("flask", "2.0.0", "3.0.0")
    rec = recommend_for_dep(dep)
    assert rec is not None
    assert rec.action == "upgrade"
    assert "3.0.0" in rec.reason


def test_recommend_for_dep_vulnerable_only():
    dep = _dep("urllib3", "1.26.0", "1.26.0", vulns=[_vuln("CVE-2023-1")])
    rec = recommend_for_dep(dep)
    assert rec is not None
    assert rec.action == "review_vulns"
    assert "CVE-2023-1" in rec.reason
    assert rec.vuln_ids == ["CVE-2023-1"]


def test_recommend_for_dep_outdated_and_vulnerable():
    dep = _dep("pip", "22.0", "24.0", vulns=[_vuln()])
    rec = recommend_for_dep(dep)
    assert rec.action == "upgrade_and_review"


def test_build_recommendations_deduplicates():
    dep = _dep("flask", "2.0.0", "3.0.0")
    fa1 = FileAudit(path="a/req.txt", deps=[dep])
    fa2 = FileAudit(path="b/req.txt", deps=[dep])
    report = AuditReport(files=[fa1, fa2])
    recs = build_recommendations(report)
    assert len(recs) == 1
    assert recs[0].package == "flask"


def test_build_recommendations_sorted_by_name():
    deps = [
        _dep("zlib", "1.0", "2.0"),
        _dep("aiohttp", "3.0", "4.0"),
        _dep("flask", "2.0", "3.0"),
    ]
    fa = FileAudit(path="req.txt", deps=deps)
    report = AuditReport(files=[fa])
    recs = build_recommendations(report)
    names = [r.package for r in recs]
    assert names == sorted(names, key=str.lower)


def test_build_recommendations_skips_clean_deps():
    deps = [_dep("requests", "2.28.0", "2.28.0"), _dep("flask", "2.0", "3.0")]
    fa = FileAudit(path="req.txt", deps=deps)
    report = AuditReport(files=[fa])
    recs = build_recommendations(report)
    assert all(r.package != "requests" for r in recs)
