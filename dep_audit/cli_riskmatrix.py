"""CLI integration for the risk matrix feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.riskmatrix import RiskMatrix, build_risk_matrix

_RISK_ORDER = ["critical", "high", "medium", "low", "ok"]


def add_riskmatrix_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("risk matrix")
    grp.add_argument(
        "--risk-matrix",
        action="store_true",
        default=False,
        help="Display a risk matrix cross-referencing outdated status and vuln severity.",
    )
    grp.add_argument(
        "--risk-matrix-format",
        choices=["text", "json"],
        default="text",
        help="Output format for the risk matrix (default: text).",
    )
    grp.add_argument(
        "--risk-min",
        choices=_RISK_ORDER,
        default="low",
        help="Minimum risk level to display (default: low).",
    )


def _render_text(matrix: RiskMatrix, min_risk: str) -> str:
    threshold = _RISK_ORDER.index(min_risk)
    lines = ["Risk Matrix", "-" * 50]
    for cell in matrix.cells:
        if _RISK_ORDER.index(cell.risk) > threshold:
            continue
        files = ", ".join(cell.source_files) or "-"
        lines.append(
            f"  [{cell.risk.upper():8s}] {cell.package:30s}  "
            f"outdated={cell.outdated_level}  vuln={cell.vuln_level}  files={files}"
        )
    if len(lines) == 2:
        lines.append("  (no entries at or above threshold)")
    return "\n".join(lines)


def _render_json(matrix: RiskMatrix, min_risk: str) -> str:
    threshold = _RISK_ORDER.index(min_risk)
    data = [
        {
            "package": c.package,
            "risk": c.risk,
            "outdated_level": c.outdated_level,
            "vuln_level": c.vuln_level,
            "source_files": c.source_files,
        }
        for c in matrix.cells
        if _RISK_ORDER.index(c.risk) <= threshold
    ]
    return json.dumps(data, indent=2)


def maybe_render_riskmatrix(
    args: argparse.Namespace,
    report: AuditReport,
) -> Optional[str]:
    """Return rendered output if --risk-matrix flag is set, else None."""
    if not getattr(args, "risk_matrix", False):
        return None
    matrix = build_risk_matrix(report)
    min_risk = getattr(args, "risk_min", "low")
    fmt = getattr(args, "risk_matrix_format", "text")
    if fmt == "json":
        return _render_json(matrix, min_risk)
    return _render_text(matrix, min_risk)
