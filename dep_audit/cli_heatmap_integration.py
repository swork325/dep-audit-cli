"""Attach heatmap CLI args and rendering to the main parser/run flow."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_heatmap import add_heatmap_args, maybe_render_heatmap


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register heatmap arguments on *parser*."""
    add_heatmap_args(parser)


def render_heatmap_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
    *,
    print_fn=print,
) -> None:
    """Render the heatmap when the user passed ``--heatmap``."""
    maybe_render_heatmap(args, report, print_fn=print_fn)
