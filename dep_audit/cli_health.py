"""CLI integration for the health-score feature."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.reporter_health import HealthScore, compute_health


def add_health_args(parser: argparse.ArgumentParser) -> None:
    """Attach --health and --health-format flags to *parser*."""
    parser.add_argument(
        "--health",
        action="store_true",
        default=False,
        help="Print an overall health score for the scanned projects.",
    )
    parser.add_argument(
        "--health-format",
        choices=["text", "json"],
        default="text",
        dest="health_format",
        help="Output format for the health score (default: text).",
    )


def _render_text(hs: HealthScore) -> str:
    lines = [
        "\n=== Dependency Health Score ===",
        f"  Grade  : {hs.grade}",
        f"  Score  : {hs.score}/100",
        f"  Deps   : {hs.total_deps}",
        f"  Outdated: {hs.outdated_count}",
        f"  Vulns  : {hs.vuln_count}",
        f"  Penalty: {hs.penalty} pts",
    ]
    return "\n".join(lines)


def _render_json(hs: HealthScore) -> str:
    return json.dumps(
        {
            "score": hs.score,
            "grade": hs.grade,
            "total_deps": hs.total_deps,
            "outdated_count": hs.outdated_count,
            "vuln_count": hs.vuln_count,
            "penalty": hs.penalty,
        },
        indent=2,
    )


def maybe_render_health(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[HealthScore]:
    """If --health was requested, compute and print the health score."""
    if not getattr(args, "health", False):
        return None

    import sys
    sink = out or sys.stdout

    hs = compute_health(report)
    fmt = getattr(args, "health_format", "text")
    text = _render_json(hs) if fmt == "json" else _render_text(hs)
    sink.write(text + "\n")
    return hs
