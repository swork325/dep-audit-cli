"""CLI integration for supply-chain risk analysis."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_supply_chain import SupplyChainReport, build_supply_chain_report


def add_supply_chain_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("supply-chain")
    grp.add_argument(
        "--supply-chain",
        action="store_true",
        default=False,
        help="Check dependencies for typosquatting / supply-chain risks.",
    )
    grp.add_argument(
        "--supply-chain-format",
        choices=["text", "json"],
        default="text",
        dest="supply_chain_format",
        help="Output format for supply-chain report (default: text).",
    )
    grp.add_argument(
        "--supply-chain-suspicious-only",
        action="store_true",
        default=False,
        dest="supply_chain_suspicious_only",
        help="Only show suspicious (typosquat candidate) packages.",
    )


def _render_text(sc_report: SupplyChainReport, suspicious_only: bool) -> str:
    lines = ["Supply-Chain Risk Report", "=" * 30]
    entries = sc_report.suspicious_entries() if suspicious_only else sc_report.entries
    if not entries:
        lines.append("No supply-chain issues detected.")
    else:
        for e in entries:
            flag = "  [SUSPICIOUS]" if e.suspicious else ""
            detail = f" (similar to '{e.typosquat_of}')" if e.typosquat_of else ""
            lines.append(f"  {e.package}=={e.version}{detail}{flag}")
    lines.append(f"\nTotal checked: {sc_report.total}  Suspicious: {sc_report.suspicious_count}")
    return "\n".join(lines)


def _render_json(sc_report: SupplyChainReport, suspicious_only: bool) -> str:
    entries = sc_report.suspicious_entries() if suspicious_only else sc_report.entries
    payload = {
        "total": sc_report.total,
        "suspicious_count": sc_report.suspicious_count,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_supply_chain(
    args: argparse.Namespace,
    report: AuditReport,
    print_fn=print,
) -> Optional[SupplyChainReport]:
    if not getattr(args, "supply_chain", False):
        return None
    sc_report = build_supply_chain_report(report)
    suspicious_only = getattr(args, "supply_chain_suspicious_only", False)
    fmt = getattr(args, "supply_chain_format", "text")
    if fmt == "json":
        print_fn(_render_json(sc_report, suspicious_only))
    else:
        print_fn(_render_text(sc_report, suspicious_only))
    return sc_report
