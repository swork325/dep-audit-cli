"""Attach supply-chain CLI args and rendering to the main parser."""
from __future__ import annotations

import argparse

from dep_audit.auditor import AuditReport
from dep_audit.cli_supply_chain import add_supply_chain_args, maybe_render_supply_chain


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register supply-chain flags on *parser*."""
    add_supply_chain_args(parser)


def render_supply_chain_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
    print_fn=print,
) -> None:
    """Render the supply-chain report when the flag is set."""
    maybe_render_supply_chain(args, report, print_fn=print_fn)
