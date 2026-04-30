"""Attach the size auditor to the main CLI parser and invoke it after scanning."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_size import add_size_args, maybe_render_size


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register --show-size and related flags on *parser*."""
    add_size_args(parser)


def render_size_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
    session=None,
) -> None:
    """Call after the main audit report is built to optionally print size data."""
    maybe_render_size(args, report, session=session)
