"""Text summary generator for audit reports."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
from dep_audit.auditor import AuditReport
from dep_audit.reporter import SummaryStats, compute_stats


@dataclass
class SummaryLine:
    label: str
    value: str


def _pct(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{100 * part / total:.1f}%"


def build_summary_lines(report: AuditReport) -> List[SummaryLine]:
    stats = compute_stats(report)
    lines = [
        SummaryLine("Total files scanned", str(stats.total_files)),
        SummaryLine("Total dependencies", str(stats.total_deps)),
        SummaryLine("Outdated", f"{stats.outdated_deps} ({_pct(stats.outdated_deps, stats.total_deps)})"),
        SummaryLine("Vulnerable", f"{stats.vulnerable_deps} ({_pct(stats.vulnerable_deps, stats.total_deps)})"),
        SummaryLine("Files with issues", f"{stats.files_with_issues} ({_pct(stats.files_with_issues, stats.total_files)})"),
        SummaryLine("Issue rate", f"{stats.issue_rate:.1f}%"),
    ]
    return lines


def render_summary_text(report: AuditReport) -> str:
    lines = build_summary_lines(report)
    width = max(len(l.label) for l in lines) + 2
    rows = [f"  {l.label:<{width}} {l.value}" for l in lines]
    header = "=== Audit Summary ==="
    return "\n".join([header] + rows)


def render_summary_json(report: AuditReport) -> dict:
    stats = compute_stats(report)
    return {
        "total_files": stats.total_files,
        "total_deps": stats.total_deps,
        "outdated_deps": stats.outdated_deps,
        "vulnerable_deps": stats.vulnerable_deps,
        "files_with_issues": stats.files_with_issues,
        "issue_rate": round(stats.issue_rate, 2),
    }
