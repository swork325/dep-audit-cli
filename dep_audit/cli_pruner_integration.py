"""Integration glue that wires the pruner CLI args into the main audit pipeline.

This module follows the same attach/apply pattern used by cli_alias_integration
and cli_classifier_integration so that the pruner can be dropped into cli.py
without cluttering that module with pruner-specific logic.
"""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

from dep_audit.cli_pruner import add_pruner_args, maybe_render_pruner

if TYPE_CHECKING:
    from dep_audit.auditor import AuditReport


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Register all pruner-related flags on *parser*.

    Call this once during parser construction so that ``--prune``,
    ``--prune-format``, and ``--src-dir`` are available to the user.

    Args:
        parser: The top-level argument parser built by ``build_parser()``.
    """
    add_pruner_args(parser)


def prune_if_requested(
    args: argparse.Namespace,
    report: "AuditReport",
) -> bool:
    """Render a prune-candidate report when the user passed ``--prune``.

    Args:
        args:   Parsed CLI namespace, expected to carry ``prune``,
                ``prune_format``, and ``src_dir`` attributes as registered
                by :func:`attach_to_parser`.
        report: The fully-resolved :class:`~dep_audit.auditor.AuditReport`
                produced by the current scan.

    Returns:
        ``True`` if the pruner output was rendered, ``False`` otherwise.
        The caller can use this to decide whether to skip the default
        formatter output.
    """
    if not getattr(args, "prune", False):
        return False

    maybe_render_pruner(args, report)
    return True
