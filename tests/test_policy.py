"""Tests for dep_audit.policy."""
from __future__ import annotations

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.policy import (
    PolicyResult,
    check_policy,
    RULE_NO_OUTDATED,
    RULE_NO_VULNERABLE,
    RULE_NO_HIGH_VULN,
)
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability


def _dep(
    name="requests",
    current="1.0.0",
    latest="2.0.0",
    is_outdated=False,
    vulns=None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        is_outdated=is_outdated,
        vulns=vulns or [],
    )


def _vuln(severity="high") -> Vulnerability:
    return Vulnerability(id="CVE-2024-0001", description="test", severity=severity)


def _report(*file_audits) -> AuditReport:
    return AuditReport(files=list(file_audits))


def _file(path, deps) -> FileAudit:
    return FileAudit(path=path, deps=deps)


# ---------------------------------------------------------------------------
# PolicyResult helpers
# ---------------------------------------------------------------------------

def test_policy_result_passed_when_no_violations():
    assert PolicyResult().passed is True


def test_policy_result_failed_when_violations_exist():
    dep = _dep(is_outdated=True)
    v = check_policy(_report(_file("r.txt", [dep])), no_outdated=True)
    assert v.passed is False


def test_policy_result_by_rule_filters_correctly():
    dep = _dep(is_outdated=True, vulns=[_vuln()])
    result = check_policy(
        _report(_file("r.txt", [dep])),
        no_outdated=True,
        no_vulnerable=True,
    )
    assert len(result.by_rule(RULE_NO_OUTDATED.name)) == 1
    assert len(result.by_rule(RULE_NO_VULNERABLE.name)) == 1


# ---------------------------------------------------------------------------
# no_outdated rule
# ---------------------------------------------------------------------------

def test_no_outdated_clean_dep_passes():
    dep = _dep(is_outdated=False)
    result = check_policy(_report(_file("r.txt", [dep])), no_outdated=True)
    assert result.passed


def test_no_outdated_flags_outdated_dep():
    dep = _dep(is_outdated=True)
    result = check_policy(_report(_file("r.txt", [dep])), no_outdated=True)
    assert not result.passed
    assert result.violations[0].rule.name == RULE_NO_OUTDATED.name


# ---------------------------------------------------------------------------
# no_vulnerable rule
# ---------------------------------------------------------------------------

def test_no_vulnerable_clean_dep_passes():
    dep = _dep(vulns=[])
    result = check_policy(_report(_file("r.txt", [dep])), no_vulnerable=True)
    assert result.passed


def test_no_vulnerable_flags_dep_with_vuln():
    dep = _dep(vulns=[_vuln("medium")])
    result = check_policy(_report(_file("r.txt", [dep])), no_vulnerable=True)
    assert not result.passed
    assert result.violations[0].rule.name == RULE_NO_VULNERABLE.name


# ---------------------------------------------------------------------------
# no_high_severity rule
# ---------------------------------------------------------------------------

def test_no_high_severity_ignores_low_vuln():
    dep = _dep(vulns=[_vuln("low")])
    result = check_policy(_report(_file("r.txt", [dep])), no_high_severity=True)
    assert result.passed


def test_no_high_severity_flags_high_vuln():
    dep = _dep(vulns=[_vuln("high")])
    result = check_policy(_report(_file("r.txt", [dep])), no_high_severity=True)
    assert not result.passed
    assert result.violations[0].rule.name == RULE_NO_HIGH_VULN.name


def test_no_high_severity_flags_critical_vuln():
    dep = _dep(vulns=[_vuln("critical")])
    result = check_policy(_report(_file("r.txt", [dep])), no_high_severity=True)
    assert not result.passed


# ---------------------------------------------------------------------------
# no flags → no violations regardless
# ---------------------------------------------------------------------------

def test_no_flags_always_passes():
    dep = _dep(is_outdated=True, vulns=[_vuln("critical")])
    result = check_policy(_report(_file("r.txt", [dep])))
    assert result.passed
