"""CLI integration for the environment-comparison feature."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_env import EnvAuditResult, compare_with_env


def add_env_args(parser: argparse.ArgumentParser) -> None:
    """Attach --env-file and --env-format flags to *parser*."""
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        default=None,
        help="Path to a pip-freeze-style environment file to compare against.",
    )
    parser.add_argument(
        "--env-format",
        choices=["text", "json"],
        default="text",
        help="Output format for environment comparison results (default: text).",
    )


def _render_text(result: EnvAuditResult) -> str:
    lines = ["Environment comparison:", ""]
    if not result.mismatches:
        lines.append("  All dependencies match the environment file.")
        return "\n".join(lines)
    for m in result.mismatches:
        if m.missing_from_env:
            lines.append(f"  MISSING FROM ENV  {m.name}  (required: {m.required_version})")
        elif m.missing_from_report:
            lines.append(f"  NOT IN REPORT     {m.name}  (env: {m.env_version})")
        else:
            lines.append(
                f"  VERSION CONFLICT  {m.name}  "
                f"required={m.required_version}  env={m.env_version}"
            )
    lines.append("")
    lines.append(f"  {len(result.conflicts)} conflict(s) found.")
    return "\n".join(lines)


def _render_json(result: EnvAuditResult) -> str:
    data = [
        {
            "name": m.name,
            "required_version": m.required_version,
            "env_version": m.env_version,
            "missing_from_env": m.missing_from_env,
            "missing_from_report": m.missing_from_report,
        }
        for m in result.mismatches
    ]
    return json.dumps({"env_mismatches": data}, indent=2)


def maybe_render_env(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    print_fn=print,
) -> Optional[EnvAuditResult]:
    """If --env-file was supplied, run comparison and print results."""
    env_file: Optional[str] = getattr(args, "env_file", None)
    if not env_file:
        return None
    result = compare_with_env(report, Path(env_file))
    fmt = getattr(args, "env_format", "text")
    output = _render_json(result) if fmt == "json" else _render_text(result)
    print_fn(output)
    return result
