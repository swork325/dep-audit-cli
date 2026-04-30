"""Attach activity auditor to the main CLI parser and run it post-scan."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_activity import add_activity_args, maybe_render_activity


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register activity CLI flags onto *parser*."""
    add_activity_args(parser)


def render_activity_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
    session=None,
) -> None:
    """Called from the main ``run`` function after the audit report is built."""
    maybe_render_activity(args, report, session=session)
