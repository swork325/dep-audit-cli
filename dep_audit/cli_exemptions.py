"""CLI integration for the exemptions feature."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
from typing import Optional

from dep_audit.exemptions import (
    Exemption,
    load_exemptions,
    save_exemptions,
    apply_exemptions,
    DEFAULT_EXEMPTIONS_FILE,
)
from dep_audit.auditor import AuditReport


def add_exemption_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("exemptions")
    grp.add_argument(
        "--exemptions-file",
        default=DEFAULT_EXEMPTIONS_FILE,
        metavar="FILE",
        help="Path to exemptions JSON file (default: %(default)s)",
    )
    grp.add_argument(
        "--apply-exemptions",
        action="store_true",
        default=False,
        help="Filter out packages covered by an active exemption",
    )
    grp.add_argument(
        "--show-exemptions",
        action="store_true",
        default=False,
        help="Print active (non-expired) exemptions and exit",
    )
    grp.add_argument(
        "--add-exemption",
        nargs=3,
        metavar=("PACKAGE", "DAYS", "REASON"),
        help="Add an exemption: package name, days until expiry, reason",
    )


def maybe_add_exemption(args: argparse.Namespace) -> bool:
    """Handle --add-exemption; returns True if action was taken."""
    if not getattr(args, "add_exemption", None):
        return False
    package, days_str, reason = args.add_exemption
    try:
        days = int(days_str)
    except ValueError:
        print(f"[exemptions] DAYS must be an integer, got {days_str!r}")
        return True
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    ex = Exemption(package=package.lower(), reason=reason, expires=expires)
    existing = load_exemptions(args.exemptions_file)
    existing.append(ex)
    save_exemptions(existing, args.exemptions_file)
    print(f"[exemptions] Added exemption for '{package}' expiring {expires.date()}")
    return True


def maybe_show_exemptions(args: argparse.Namespace) -> bool:
    """Handle --show-exemptions; returns True if action was taken."""
    if not getattr(args, "show_exemptions", False):
        return False
    exemptions = load_exemptions(args.exemptions_file)
    now = datetime.now(timezone.utc)
    active = [e for e in exemptions if not e.is_expired(now)]
    expired = [e for e in exemptions if e.is_expired(now)]
    print(f"Active exemptions ({len(active)}):")
    for e in active:
        print(f"  {e.package:30s}  expires {e.expires.date()}  — {e.reason}")
    if expired:
        print(f"Expired exemptions ({len(expired)}):")
        for e in expired:
            print(f"  {e.package:30s}  expired {e.expires.date()}")
    return True


def maybe_apply_exemptions(args: argparse.Namespace, report: AuditReport) -> AuditReport:
    """Return a filtered report if --apply-exemptions is set."""
    if not getattr(args, "apply_exemptions", False):
        return report
    exemptions = load_exemptions(args.exemptions_file)
    return apply_exemptions(report, exemptions)
