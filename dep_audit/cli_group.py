"""CLI helpers to display grouped report output."""
from __future__ import annotations
import argparse
from dep_audit.grouper import group_report, GroupedReport
from dep_audit.auditor import AuditReport


def add_group_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--group-by",
        choices=["package", "severity", "file"],
        default=None,
        help="Group output by package, severity, or file.",
    )


def render_grouped(report: AuditReport, group_by: str) -> str:
    gr: GroupedReport = group_report(report)
    lines = []
    if group_by == "package":
        for pkg, audits in sorted(gr.by_package.items()):
            files = ", ".join(a.path for a in audits)
            lines.append(f"[{pkg}] found in: {files}")
    elif group_by == "severity":
        for sev, deps in sorted(gr.by_severity.items()):
            names = ", ".join(d.name for d in deps)
            lines.append(f"[{sev}] {names}")
    elif group_by == "file":
        for path, fa in sorted(gr.by_file.items()):
            dep_names = ", ".join(d.name for d in fa.deps)
            lines.append(f"[{path}] {dep_names}")
    return "\n".join(lines)
