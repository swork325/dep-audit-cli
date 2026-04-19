"""Tests for dep_audit.comparator."""
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.comparator import compare_reports, DepChange


def _dep(name: str, version: str) -> ResolvedDep:
    return ResolvedDep(name=name, version=version, latest=version, vulnerabilities=[])


def _report(*pairs: tuple) -> AuditReport:
    """Build a minimal AuditReport from (name, version) pairs."""
    deps = [_dep(name, ver) for name, ver in pairs]
    fa = FileAudit(path="requirements.txt", deps=deps)
    return AuditReport(files=[fa])


def test_no_changes_empty_result():
    old = _report(("requests", "2.28.0"), ("flask", "2.0.0"))
    new = _report(("requests", "2.28.0"), ("flask", "2.0.0"))
    result = compare_reports(old, new)
    assert not result.has_changes
    assert result.total_changes == 0


def test_added_package():
    old = _report(("requests", "2.28.0"))
    new = _report(("requests", "2.28.0"), ("flask", "2.0.0"))
    result = compare_reports(old, new)
    assert len(result.added) == 1
    assert result.added[0].package == "flask"
    assert result.added[0].old_version is None
    assert result.added[0].new_version == "2.0.0"
    assert result.added[0].change_type == "added"


def test_removed_package():
    old = _report(("requests", "2.28.0"), ("flask", "2.0.0"))
    new = _report(("requests", "2.28.0"))
    result = compare_reports(old, new)
    assert len(result.removed) == 1
    assert result.removed[0].package == "flask"
    assert result.removed[0].new_version is None
    assert result.removed[0].change_type == "removed"


def test_upgraded_package():
    old = _report(("requests", "2.28.0"))
    new = _report(("requests", "2.31.0"))
    result = compare_reports(old, new)
    assert len(result.upgraded) == 1
    c = result.upgraded[0]
    assert c.old_version == "2.28.0"
    assert c.new_version == "2.31.0"
    assert c.change_type == "upgraded"


def test_downgraded_package():
    old = _report(("requests", "2.31.0"))
    new = _report(("requests", "2.28.0"))
    result = compare_reports(old, new)
    assert len(result.downgraded) == 1
    c = result.downgraded[0]
    assert c.old_version == "2.31.0"
    assert c.new_version == "2.28.0"
    assert c.change_type == "downgraded"


def test_total_changes_counts_all_categories():
    old = _report(("requests", "2.28.0"), ("flask", "2.0.0"))
    new = _report(("requests", "2.31.0"), ("django", "4.2.0"))
    result = compare_reports(old, new)
    # flask removed, django added, requests upgraded
    assert result.total_changes == 3
    assert result.has_changes


def test_case_insensitive_package_names():
    old = _report(("Requests", "2.28.0"))
    new = _report(("requests", "2.31.0"))
    result = compare_reports(old, new)
    assert len(result.upgraded) == 1
    assert not result.added
    assert not result.removed
