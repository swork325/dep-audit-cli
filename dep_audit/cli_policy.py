"""CLI integration for the policy engine."""
from __future__ import annotations

import argparse
import sys
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.policy import PolicyResult, check_policy


def add_policy_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("policy")
    grp.add_argument(
        "--policy-no-outdated",
        action="store_true",
        default=False,
        help="Fail if any dependency is outdated.",
    )
    grp.add_argument(
        "--policy-no-vulnerable",
        action="store_true",
        default=False,
        help="Fail if any dependency has vulnerabilities.",
    )
    grp.add_argument(
        "--policy-no-high-severity",
        action="store_true",
        default=False,
        help="Fail if any dependency has high/critical vulnerabilities.",
    )


def evaluate_policy(
    args: argparse.Namespace,
    report: AuditReport,
) -> Optional[PolicyResult]:
    if not (args.policy_no_outdated or args.policy_no_vulnerable or args.policy_no_high_severity):
        return None
    return check_policy(
        report,
        no_outdated=args.policy_no_outdated,
        no_vulnerable=args.policy_no_vulnerable,
        no_high_severity=args.policy_no_high_severity,
    )


def render_policy_result(result: PolicyResult) -> str:
    if result.passed:
        return "Policy check passed — no violations found.\n"
    lines = [f"Policy check FAILED — {len(result.violations)} violation(s):\n"]
    for v in result.violations:
        lines.append(f"  [{v.rule.name}] {v.file_path}: {v.detail}")
    return "\n".join(lines) + "\n"


def maybe_enforce_policy(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    exit_on_failure: bool = False,
) -> Optional[PolicyResult]:
    result = evaluate_policy(args, report)
    if result is None:
        return None
    print(render_policy_result(result), end="")
    if exit_on_failure and not result.passed:
        sys.exit(1)
    return result
