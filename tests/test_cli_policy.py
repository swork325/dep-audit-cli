"""Tests for dep_audit.cli_policy."""
from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.cli_policy import (
    add_policy_args,
    evaluate_policy,
    render_policy_result,
    maybe_enforce_policy,
)
from dep_audit.policy import PolicyResult, PolicyViolation, RULE_NO_OUTDATED
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability


def _parse(*argv) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    add_policy_args(p)
    return p.parse_args(list(argv))


def _dep(is_outdated=False, vulns=None) -> ResolvedDep:
    return ResolvedDep(
        name="requests",
        current_version="1.0",
        latest_version="2.0",
        is_outdated=is_outdated,
        vulns=vulns or [],
    )


def _report(dep) -> AuditReport:
    return AuditReport(files=[FileAudit(path="r.txt", deps=[dep])])


# ---------------------------------------------------------------------------
# add_policy_args defaults
# ---------------------------------------------------------------------------

def test_defaults_all_false():
    args = _parse()
    assert args.policy_no_outdated is False
    assert args.policy_no_vulnerable is False
    assert args.policy_no_high_severity is False


def test_no_outdated_flag_sets_true():
    args = _parse("--policy-no-outdated")
    assert args.policy_no_outdated is True


def test_no_vulnerable_flag_sets_true():
    args = _parse("--policy-no-vulnerable")
    assert args.policy_no_vulnerable is True


def test_no_high_severity_flag_sets_true():
    args = _parse("--policy-no-high-severity")
    assert args.policy_no_high_severity is True


# ---------------------------------------------------------------------------
# evaluate_policy
# ---------------------------------------------------------------------------

def test_evaluate_policy_returns_none_when_no_flags():
    args = _parse()
    assert evaluate_policy(args, _report(_dep())) is None


def test_evaluate_policy_returns_result_when_flag_set():
    args = _parse("--policy-no-outdated")
    result = evaluate_policy(args, _report(_dep(is_outdated=True)))
    assert result is not None
    assert not result.passed


# ---------------------------------------------------------------------------
# render_policy_result
# ---------------------------------------------------------------------------

def test_render_passed_message():
    text = render_policy_result(PolicyResult())
    assert "passed" in text


def test_render_shows_violation_detail():
    dep = _dep(is_outdated=True)
    v = PolicyViolation(rule=RULE_NO_OUTDATED, file_path="r.txt", dep=dep, detail="requests 1.0 < 2.0")
    result = PolicyResult(violations=[v])
    text = render_policy_result(result)
    assert "FAILED" in text
    assert "no-outdated" in text
    assert "requests 1.0 < 2.0" in text


# ---------------------------------------------------------------------------
# maybe_enforce_policy
# ---------------------------------------------------------------------------

def test_maybe_enforce_policy_returns_none_when_no_flags():
    args = _parse()
    assert maybe_enforce_policy(args, _report(_dep())) is None


def test_maybe_enforce_policy_exits_on_failure(capsys):
    args = _parse("--policy-no-outdated")
    with pytest.raises(SystemExit) as exc_info:
        maybe_enforce_policy(args, _report(_dep(is_outdated=True)), exit_on_failure=True)
    assert exc_info.value.code == 1


def test_maybe_enforce_policy_no_exit_when_passed(capsys):
    args = _parse("--policy-no-outdated")
    result = maybe_enforce_policy(args, _report(_dep(is_outdated=False)), exit_on_failure=True)
    assert result is not None
    assert result.passed
