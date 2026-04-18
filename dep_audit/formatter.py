"""Format audit reports as human-readable text or JSON."""
from __future__ import annotations

import json
from typing import Literal

from dep_audit.auditor import AuditReport
from dep_audit.reporter import summarize, SummaryStats


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEVERITY_COLOURS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[96m",
}
_RESET = "\033[0m"


def _severity_label(severity: str | None) -> str:
    colour = _SEVERITY_COLOURS.get((severity or "").upper(), "")
    label = (severity or "UNKNOWN").upper()
    return f"{colour}[{label}]{_RESET}" if colour else f"[{label}]"


def format_text(report: AuditReport, *, colour: bool = True) -> str:
    summary = summarize(report)
    lines: list[str] = []

    for fa in report.file_audits:
        if not fa.has_issues:
            continue
        lines.append(f"\n=== {fa.path} ===")
        for dep in fa.deps:
            outdated = dep.latest and dep.installed != dep.latest
            if outdated:
                lines.append(f"  {dep.name}: {dep.installed} -> {dep.latest} (outdated)")
            for v in dep.vulns:
                label = _severity_label(v.severity) if colour else f"[{v.severity or 'UNKNOWN'}]"
                lines.append(f"  {dep.name}: {label} {v.vuln_id} — {v.description or 'no description'}")

    stats: SummaryStats = summary.stats
    lines.append(
        f"\nSummary: {stats.total_files} file(s) scanned, "
        f"{stats.files_with_issues} with issues, "
        f"{stats.outdated_count} outdated, "
        f"{stats.vulnerable_count} vulnerable dep(s)."
    )
    return "\n".join(lines)


def format_json(report: AuditReport) -> str:
    summary = summarize(report)
    data = {
        "stats": {
            "total_files": summary.stats.total_files,
            "files_with_issues": summary.stats.files_with_issues,
            "total_deps": summary.stats.total_deps,
            "outdated": summary.stats.outdated_count,
            "vulnerable": summary.stats.vulnerable_count,
            "unique_vulnerabilities": summary.stats.unique_vulnerabilities,
        },
        "files": [
            {
                "path": fa.path,
                "deps": [
                    {
                        "name": d.name,
                        "installed": d.installed,
                        "latest": d.latest,
                        "outdated": bool(d.latest and d.installed != d.latest),
                        "vulnerabilities": [
                            {
                                "id": v.vuln_id,
                                "severity": v.severity,
                                "description": v.description,
                                "fix_version": v.fix_version,
                            }
                            for v in d.vulns
                        ],
                    }
                    for d in fa.deps
                ],
            }
            for fa in report.file_audits
        ],
    }
    return json.dumps(data, indent=2)


def render(report: AuditReport, fmt: str = "text", *, colour: bool = True) -> str:
    if fmt == "json":
        return format_json(report)
    return format_text(report, colour=colour)
