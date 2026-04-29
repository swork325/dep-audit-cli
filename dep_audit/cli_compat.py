"""CLI integration for the Python-version compatibility checker."""
from __future__ import annotations

import argparse
import json
import platform
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_compat import CompatReport, build_compat_report


def add_compat_args(parser: argparse.ArgumentParser) -> None:
    """Attach --compat / --compat-runtime / --compat-format flags."""
    grp = parser.add_argument_group("compatibility")
    grp.add_argument(
        "--compat",
        action="store_true",
        default=False,
        help="Check Python version compatibility for every dependency.",
    )
    grp.add_argument(
        "--compat-runtime",
        metavar="VERSION",
        default=None,
        help="Python version to check against (default: running interpreter).",
    )
    grp.add_argument(
        "--compat-format",
        choices=["text", "json"],
        default="text",
        help="Output format for compatibility report (default: text).",
    )


def _runtime(args: argparse.Namespace) -> str:
    if args.compat_runtime:
        return args.compat_runtime
    v = platform.python_version_tuple()
    return f"{v[0]}.{v[1]}"


def _render_text(compat: CompatReport, runtime: str) -> str:
    lines = [f"Python {runtime} compatibility ({compat.total} packages checked)"]
    if not compat.incompatible:
        lines.append("  All dependencies are compatible.")
    else:
        for e in compat.incompatible:
            pin = e.current_version or "unpinned"
            lines.append(f"  [INCOMPATIBLE] {e.package} {pin} — {e.reason}")
    return "\n".join(lines)


def _render_json(compat: CompatReport, runtime: str) -> str:
    payload = {
        "runtime": runtime,
        "total": compat.total,
        "incompatible_count": compat.incompatible_count,
        "entries": [e.to_dict() for e in compat.entries],
    }
    return json.dumps(payload, indent=2)


def maybe_render_compat(
    args: argparse.Namespace,
    report: AuditReport,
    extras_map: Optional[dict] = None,
) -> None:
    if not getattr(args, "compat", False):
        return
    runtime = _runtime(args)
    compat = build_compat_report(report, runtime, extras_map)
    fmt = getattr(args, "compat_format", "text")
    if fmt == "json":
        print(_render_json(compat, runtime))
    else:
        print(_render_text(compat, runtime))
