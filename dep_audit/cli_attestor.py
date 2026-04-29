"""cli_attestor.py – CLI integration for package attestation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dep_audit.attestor import (
    AttestationReport,
    build_attestation_report,
    load_attestation_map,
)
from dep_audit.auditor import AuditReport


def add_attestor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--attest",
        action="store_true",
        default=False,
        help="Verify packages against a SHA-256 attestation map.",
    )
    parser.add_argument(
        "--attest-file",
        default=".dep_attestations.json",
        metavar="FILE",
        help="Path to the attestation map JSON file (default: .dep_attestations.json).",
    )
    parser.add_argument(
        "--attest-format",
        choices=["text", "json"],
        default="text",
        help="Output format for attestation results.",
    )
    parser.add_argument(
        "--attest-fail-on-mismatch",
        action="store_true",
        default=False,
        help="Exit with code 2 if any attestation fails.",
    )


def _render_text(attest_report: AttestationReport) -> str:
    lines = ["Attestation Report", "=================="]
    for entry in attest_report.entries:
        status = "✓ VERIFIED" if entry.verified else "✗ MISMATCH"
        lines.append(f"  {entry.name}=={entry.version}  [{status}]")
        if not entry.verified:
            lines.append(f"    expected: {entry.expected_sha256 or '(none)'}")
            lines.append(f"    actual:   {entry.actual_sha256 or '(none)'}")
    lines.append("")
    lines.append(
        f"Summary: {attest_report.verified_count}/{attest_report.total} verified, "
        f"{attest_report.failed_count} failed."
    )
    return "\n".join(lines)


def _render_json(attest_report: AttestationReport) -> str:
    return json.dumps(
        {
            "total": attest_report.total,
            "verified": attest_report.verified_count,
            "failed": attest_report.failed_count,
            "all_verified": attest_report.all_verified,
            "entries": [e.to_dict() for e in attest_report.entries],
        },
        indent=2,
    )


def maybe_render_attestation(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> int:
    """Render attestation output if --attest is requested.

    Returns an exit code (0 or 2); callers should OR this with their own code.
    """
    if not getattr(args, "attest", False):
        return 0

    if out is None:
        out = sys.stdout

    attest_map = load_attestation_map(Path(args.attest_file))
    attest_report = build_attestation_report(report, attest_map)

    if args.attest_format == "json":
        print(_render_json(attest_report), file=out)
    else:
        print(_render_text(attest_report), file=out)

    if args.attest_fail_on_mismatch and not attest_report.all_verified:
        return 2
    return 0
