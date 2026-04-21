"""Wires alias resolution into the main CLI pipeline.

Usage in cli.py::

    from dep_audit.cli_alias_integration import attach_to_parser, apply_aliases_if_requested

    attach_to_parser(parser)
    report = apply_aliases_if_requested(report, args)
"""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_alias import add_alias_args, maybe_apply_aliases


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register alias flags on *parser* (idempotent group label)."""
    group = parser.add_argument_group("alias options")
    add_alias_args(group)  # type: ignore[arg-type]


def apply_aliases_if_requested(
    report: AuditReport, args: argparse.Namespace
) -> AuditReport:
    """Apply alias resolution to *report* when the user has opted in.

    Returns the original report unchanged when no alias flags were supplied.
    """
    return maybe_apply_aliases(report, args)
