"""CLI helpers for label-based filtering and display."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.labeler import filter_by_label, label_report, load_label_map


def add_label_args(parser: argparse.ArgumentParser) -> None:
    """Register label-related CLI arguments on *parser*."""
    parser.add_argument(
        "--filter-label",
        metavar="LABEL",
        default=None,
        help="Only show deps that carry this label.",
    )
    parser.add_argument(
        "--label-map",
        metavar="FILE",
        default=".dep_labels.json",
        help="Path to the label map JSON file (default: .dep_labels.json).",
    )
    parser.add_argument(
        "--show-labels",
        action="store_true",
        default=False,
        help="Print a summary of all labels and their matched deps.",
    )


def maybe_print_labels(
    args: argparse.Namespace, report: AuditReport
) -> None:
    """If --show-labels is set, print label -> dep summary to stdout."""
    if not getattr(args, "show_labels", False):
        return
    label_map_path = Path(args.label_map)
    if not label_map_path.exists():
        print(f"Warning: label map file '{label_map_path}' not found; skipping label summary.")
        return
    label_map = load_label_map(label_map_path)
    grouped = label_report(report, label_map)
    if not grouped:
        print("No labels matched any dependencies.")
        return
    for label, deps in sorted(grouped.items()):
        names = ", ".join(sorted({d.name for d in deps}))
        print(f"[{label}] {names}")


def apply_label_filter(
    args: argparse.Namespace, report: AuditReport
) -> Optional[list]:
    """Return filtered dep list when --filter-label is set, else None."""
    label = getattr(args, "filter_label", None)
    if not label:
        return None
    label_map_path = Path(args.label_map)
    if not label_map_path.exists():
        raise FileNotFoundError(
            f"Label map file '{label_map_path}' not found. "
            "Provide a valid path via --label-map."
        )
    label_map = load_label_map(label_map_path)
    return filter_by_label(report, label, label_map)
