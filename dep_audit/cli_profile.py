"""CLI helpers to render per-package profiles."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.profiler import DepProfile, build_profiles


def add_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        action="store_true",
        default=False,
        help="Show per-package profile summary.",
    )
    parser.add_argument(
        "--profile-format",
        choices=["text", "json"],
        default="text",
        help="Output format for profiles (default: text).",
    )


def _render_profile_text(prof: DepProfile) -> str:
    lines = [f"Package : {prof.name}"]
    lines.append(f"  Versions  : {', '.join(prof.current_versions) or 'unknown'}")
    lines.append(f"  Latest    : {prof.latest_version or 'unknown'}")
    lines.append(f"  Outdated  : {'yes' if prof.is_outdated else 'no'}")
    lines.append(f"  Vulns     : {prof.vuln_count}")
    if prof.highest_severity:
        lines.append(f"  Severity  : {prof.highest_severity}")
    lines.append(f"  Files     : {prof.file_count}")
    return "\n".join(lines)


def render_profiles(report: AuditReport, fmt: str = "text") -> str:
    profiles = build_profiles(report)
    if not profiles:
        return "No packages found."

    if fmt == "json":
        data = [
            {
                "name": p.name,
                "current_versions": p.current_versions,
                "latest_version": p.latest_version,
                "is_outdated": p.is_outdated,
                "vuln_count": p.vuln_count,
                "highest_severity": p.highest_severity,
                "files": p.files,
            }
            for p in sorted(profiles.values(), key=lambda x: x.name.lower())
        ]
        return json.dumps(data, indent=2)

    blocks = [
        _render_profile_text(p)
        for p in sorted(profiles.values(), key=lambda x: x.name.lower())
    ]
    return "\n\n".join(blocks)


def maybe_render_profiles(
    args: argparse.Namespace, report: AuditReport
) -> Optional[str]:
    if not getattr(args, "profile", False):
        return None
    fmt = getattr(args, "profile_format", "text")
    return render_profiles(report, fmt=fmt)
