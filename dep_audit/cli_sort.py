"""CLI helpers for --sort-by / --sort-desc flags."""
from __future__ import annotations

import argparse
from dep_audit.sorter import SortConfig, SortKey

_VALID_KEYS = ("name", "severity", "outdated", "file")


def add_sort_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sort-by",
        choices=_VALID_KEYS,
        default=None,
        dest="sort_by",
        help="Sort dependencies by this field.",
    )
    parser.add_argument(
        "--sort-desc",
        action="store_true",
        default=False,
        dest="sort_desc",
        help="Reverse the sort order.",
    )


def sort_config_from_args(args: argparse.Namespace) -> SortConfig | None:
    """Return a SortConfig if sorting was requested, else None."""
    key: SortKey | None = getattr(args, "sort_by", None)
    if key is None:
        return None
    return SortConfig(key=key, reverse=getattr(args, "sort_desc", False))
