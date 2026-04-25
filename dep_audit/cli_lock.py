"""CLI helpers for the lock-file consistency feature."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from dep_audit.auditor_lock import LockInconsistency, LockReport


def add_lock_args(parser: argparse.ArgumentParser) -> None:
    """Attach lock-file arguments to *parser*."""
    parser.add_argument(
        "--lock-file",
        metavar="PATH",
        default=None,
        help="Path to a pinned requirements / lock file to check consistency against.",
    )
    parser.add_argument(
        "--lock-format",
        choices=["text", "json"],
        default="text",
        help="Output format for lock-file inconsistency report (default: text).",
    )


def _render_text(report: LockReport) -> str:
    lines: List[str] = [f"Lock-file: {report.lock_file}"]
    if report.is_consistent:
        lines.append("  ✔ All audited packages are consistent with the lock file.")
    else:
        lines.append(f"  ✘ {report.total} inconsistency(ies) found:")
        for inc in report.inconsistencies:
            locked = inc.locked_version or "<missing>"
            latest = inc.latest_version or "unknown"
            lines.append(f"    • {inc.name}: {inc.reason}  (locked={locked}, latest={latest})")
    return "\n".join(lines)


def _render_json(report: LockReport) -> str:
    data = {
        "lock_file": report.lock_file,
        "is_consistent": report.is_consistent,
        "total_inconsistencies": report.total,
        "inconsistencies": [
            {
                "name": i.name,
                "locked_version": i.locked_version,
                "latest_version": i.latest_version,
                "reason": i.reason,
            }
            for i in report.inconsistencies
        ],
    }
    return json.dumps(data, indent=2)


def maybe_render_lock(
    args: argparse.Namespace,
    deps,
    print_fn=print,
) -> None:
    """If ``--lock-file`` was supplied, run the check and print results."""
    lock_path_str: str | None = getattr(args, "lock_file", None)
    if not lock_path_str:
        return

    from dep_audit.auditor_lock import check_lock_consistency

    lock_path = Path(lock_path_str)
    report = check_lock_consistency(deps, lock_path)
    fmt = getattr(args, "lock_format", "text")
    if fmt == "json":
        print_fn(_render_json(report))
    else:
        print_fn(_render_text(report))
