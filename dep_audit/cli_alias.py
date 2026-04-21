"""CLI helpers for the alias-resolution feature."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from dep_audit.aliaser import AliasMap, alias_report, load_alias_map
from dep_audit.auditor import AuditReport


def add_alias_args(parser: argparse.ArgumentParser) -> None:
    """Attach alias-related flags to *parser*."""
    parser.add_argument(
        "--alias-map",
        metavar="FILE",
        default=None,
        help="Path to a JSON file mapping package aliases to canonical names.",
    )
    parser.add_argument(
        "--no-default-aliases",
        action="store_true",
        default=False,
        help="Disable the built-in alias table (only user-supplied aliases apply).",
    )


def alias_map_from_args(args: argparse.Namespace) -> Optional[AliasMap]:
    """Build an AliasMap from parsed CLI args, or return None if unused."""
    path: Optional[Path] = Path(args.alias_map) if args.alias_map else None
    if path is None and not args.no_default_aliases:
        return None  # caller should skip aliasing entirely
    alias_map = load_alias_map(path)
    if args.no_default_aliases:
        # Reload without defaults
        from dep_audit.aliaser import AliasMap as _AM
        user_only: _AM = {}
        if path and path.exists():
            import json
            try:
                data = json.loads(path.read_text())
                if isinstance(data, dict):
                    user_only = {str(k).lower(): str(v) for k, v in data.items()}
            except Exception:
                pass
        return user_only
    return alias_map


def maybe_apply_aliases(
    report: AuditReport, args: argparse.Namespace
) -> AuditReport:
    """Apply alias resolution to *report* when requested via *args*."""
    alias_map = alias_map_from_args(args)
    if alias_map is None:
        return report
    return alias_report(report, alias_map)
