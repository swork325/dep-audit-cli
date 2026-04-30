"""Wires churn reporting into the main CLI parser and run loop."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_churn import add_churn_args, maybe_render_churn


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register churn arguments on *parser*."""
    add_churn_args(parser)


def render_churn_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
) -> None:
    """Render churn output when the --churn flag is present."""
    maybe_render_churn(args, report)
