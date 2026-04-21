"""cli_digest.py – CLI integration for the report digester.

Adds ``--digest`` and ``--digest-short`` flags to the main parser and
provides helpers to print the digest after a scan.
"""
from __future__ import annotations

import argparse
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.digester import ReportDigest, compute_digest


def add_digest_args(parser: argparse.ArgumentParser) -> None:
    """Register digest-related flags on *parser*."""
    group = parser.add_argument_group("digest")
    group.add_argument(
        "--digest",
        action="store_true",
        default=False,
        help="Print the SHA-256 digest of the scanned report.",
    )
    group.add_argument(
        "--digest-short",
        action="store_true",
        default=False,
        help="Print only the first 12 characters of the digest.",
    )
    group.add_argument(
        "--digest-length",
        type=int,
        default=12,
        metavar="N",
        help="Number of characters to show with --digest-short (default: 12).",
    )


def maybe_print_digest(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    out=None,
) -> Optional[ReportDigest]:
    """Compute and optionally print the digest based on *args*.

    Returns the :class:`ReportDigest` when either flag is active, else ``None``.
    """
    import sys

    if out is None:
        out = sys.stdout

    if not (args.digest or args.digest_short):
        return None

    digest = compute_digest(report)

    if args.digest_short:
        length = getattr(args, "digest_length", 12)
        out.write(f"digest: {digest.short(length)}  ({digest.entry_count} deps)\n")
    else:
        out.write(f"digest: {digest.hex}  ({digest.entry_count} deps)\n")

    return digest
