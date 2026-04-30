"""CLI integration for dependency churn reporting."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.auditor_churn import ChurnReport, build_churn_report

_DEFAULT_THRESHOLD = 3
_DEFAULT_HISTORY_FILE = ".dep_audit_churn.json"


def add_churn_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--churn", action="store_true", default=False,
                        help="Show dependency churn analysis.")
    parser.add_argument("--churn-threshold", type=int, default=_DEFAULT_THRESHOLD,
                        metavar="N",
                        help="Minimum version changes to mark a dep as frequent (default: 3).")
    parser.add_argument("--churn-history", default=_DEFAULT_HISTORY_FILE,
                        metavar="FILE",
                        help="JSON file storing per-package change counts.")
    parser.add_argument("--churn-format", choices=["text", "json"], default="text",
                        help="Output format for churn report.")


def _load_history(path: str) -> dict[str, int]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {str(k): int(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_history(path: str, history: dict[str, int]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2)


def _update_history(history: dict[str, int], churn: ChurnReport) -> dict[str, int]:
    updated = dict(history)
    for entry in churn.entries:
        key = entry.name.lower().replace("-", "_")
        if entry.latest_version and entry.current_version != entry.latest_version:
            updated[key] = updated.get(key, 0) + 1
    return updated


def _render_text(churn: ChurnReport) -> str:
    lines = ["Dependency Churn Report", "=" * 30]
    if not churn.entries:
        lines.append("  No dependencies found.")
        return "\n".join(lines)
    for e in churn.entries:
        flag = " [FREQUENT]" if e.is_frequent else ""
        lines.append(f"  {e.name} ({e.current_version or '?'}) changes={e.change_count}{flag}")
    lines.append(f"\nTotal: {churn.total}  Frequent: {churn.frequent_count}")
    return "\n".join(lines)


def _render_json(churn: ChurnReport) -> str:
    return json.dumps(
        {"total": churn.total, "frequent_count": churn.frequent_count,
         "entries": [e.to_dict() for e in churn.entries]},
        indent=2,
    )


def maybe_render_churn(
    args: argparse.Namespace,
    report: AuditReport,
    out=None,
) -> Optional[ChurnReport]:
    import sys
    if not getattr(args, "churn", False):
        return None
    sink = out or sys.stdout
    history = _load_history(args.churn_history)
    churn = build_churn_report(report, history, threshold=args.churn_threshold)
    updated = _update_history(history, churn)
    _save_history(args.churn_history, updated)
    text = _render_json(churn) if args.churn_format == "json" else _render_text(churn)
    print(text, file=sink)
    return churn
