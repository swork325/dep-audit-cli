"""Attach ownership args to the main CLI parser and invoke rendering."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_ownership import add_ownership_args, maybe_render_ownership


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register ownership flags on *parser*."""
    add_ownership_args(parser)


def render_ownership_if_requested(
    args: argparse.Namespace, report: AuditReport
) -> None:
    """Call :func:`maybe_render_ownership` when the flag is set."""
    maybe_render_ownership(args, report)
