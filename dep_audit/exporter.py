"""Export audit reports to various file formats (JSON, CSV)."""
from __future__ import annotations

import csv
import io
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dep_audit.auditor import AuditReport


def export_json(report: "AuditReport") -> str:
    """Serialize an AuditReport to a JSON string."""
    data = {
        "files": [
            {
                "path": fa.path,
                "dependencies": [
                    {
                        "name": d.name,
                        "current_version": d.current_version,
                        "latest_version": d.latest_version,
                        "is_outdated": d.is_outdated,
                        "vulnerabilities": [
                            {"id": v.vuln_id, "description": v.description}
                            for v in (d.vulnerabilities or [])
                        ],
                    }
                    for d in fa.deps
                ],
            }
            for fa in report.files
        ]
    }
    return json.dumps(data, indent=2)


def export_csv(report: "AuditReport") -> str:
    """Serialize an AuditReport to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["file", "package", "current_version", "latest_version", "is_outdated", "vuln_ids"]
    )
    for fa in report.files:
        for d in fa.deps:
            vuln_ids = ";".join(v.vuln_id for v in (d.vulnerabilities or []))
            writer.writerow(
                [
                    fa.path,
                    d.name,
                    d.current_version,
                    d.latest_version,
                    d.is_outdated,
                    vuln_ids,
                ]
            )
    return output.getvalue()


def export(report: "AuditReport", fmt: str) -> str:
    """Export report in the given format ('json' or 'csv')."""
    if fmt == "json":
        return export_json(report)
    if fmt == "csv":
        return export_csv(report)
    raise ValueError(f"Unsupported export format: {fmt!r}")
