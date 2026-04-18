"""Integration wiring: attach group rendering into the main CLI run flow."""
from __future__ import annotations
import argparse
from typing import Optional
from dep_audit.auditor import AuditReport
from dep_audit.cli_group import add_group_args, render_grouped


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Attach --group-by argument to an existing parser."""
    add_group_args(parser)


def maybe_render_grouped(report: AuditReport, group_by: Optional[str]) -> Optional[str]:
    """Return grouped rendering string if group_by is set, else None."""
    if not group_by:
        return None
    return render_grouped(report, group_by)


def print_grouped_if_requested(report: AuditReport, args: argparse.Namespace) -> bool:
    """Print grouped output if --group-by was supplied. Returns True if printed."""
    group_by = getattr(args, "group_by", None)
    output = maybe_render_grouped(report, group_by)
    if output is not None:
        print(output)
        return True
    return False
