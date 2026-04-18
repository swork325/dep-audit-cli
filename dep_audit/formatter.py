"""Output formatters for audit reports."""
from __future__ import annotations

import json
from typing import Literal

from dep_audit.auditor import AuditReport, FileAudit

OutputFormat = Literal["text", "json"]


def _severity_label(dep_file: FileAudit) -> str:
    if any(d.vulnerabilities for d in dep_file.deps):
        return "VULNERABLE"
    if dep_file.outdated:
        return "OUTDATED"
    return "OK"


def format_text(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append(f"Audit Report — {len(report.files)} file(s) scanned")
    lines.append("=" * 50)
    for file_audit in report.files:
        label = _severity_label(file_audit)
        lines.append(f"\n[{label}] {file_audit.path}")
        if not file_audit.deps:
            lines.append("  No dependencies found.")
            continue
        for dep in file_audit.deps:
            status_parts = []
            if dep.is_outdated:
                status_parts.append(f"outdated ({dep.current} → {dep.latest})")
            if dep.vulnerabilities:
                vuln_ids = ", ".join(dep.vulnerabilities)
                status_parts.append(f"vulnerable [{vuln_ids}]")
            status = "; ".join(status_parts) if status_parts else "ok"
            lines.append(f"  {dep.name}=={dep.current}  {status}")
    lines.append("\n" + "=" * 50)
    lines.append(
        f"Total: {report.total_deps} deps, "
        f"{report.total_outdated} outdated, "
        f"{report.total_vulnerable} vulnerable"
    )
    return "\n".join(lines)


def format_json(report: AuditReport) -> str:
    data = {
        "summary": {
            "files_scanned": len(report.files),
            "total_deps": report.total_deps,
            "total_outdated": report.total_outdated,
            "total_vulnerable": report.total_vulnerable,
        },
        "files": [
            {
                "path": fa.path,
                "status": _severity_label(fa),
                "deps": [
                    {
                        "name": d.name,
                        "current": d.current,
                        "latest": d.latest,
                        "is_outdated": d.is_outdated,
                        "vulnerabilities": d.vulnerabilities,
                    }
                    for d in fa.deps
                ],
            }
            for fa in report.files
        ],
    }
    return json.dumps(data, indent=2)


def render(report: AuditReport, fmt: OutputFormat = "text") -> str:
    if fmt == "json":
        return format_json(report)
    return format_text(report)
