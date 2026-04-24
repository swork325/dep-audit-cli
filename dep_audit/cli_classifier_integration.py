"""Integration helpers that wire the classifier into the main CLI pipeline.

This module provides the attach/apply pattern used by other integration
modules (e.g. cli_alias_integration, cli_group_integration) so that the
classifier can be dropped into cli.py with minimal coupling.
"""

from __future__ import annotations

import argparse
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.classifier import ClassificationReport, classify_report
from dep_audit.cli_classifier import add_classifier_args, maybe_render_classification


def attach_to_parser(parser: argparse.ArgumentParser) -> None:
    """Add classifier-related flags to *parser*.

    Call this once during parser construction so that ``--classify``,
    ``--classify-format``, and related flags are available on the CLI.

    Args:
        parser: The top-level argument parser for dep-audit-cli.
    """
    add_classifier_args(parser)


def classify_if_requested(
    args: argparse.Namespace,
    report: AuditReport,
) -> Optional[ClassificationReport]:
    """Build and optionally render a :class:`ClassificationReport`.

    If the user did not pass ``--classify`` this function is a no-op and
    returns ``None``.  Otherwise it classifies every dependency in *report*,
    delegates rendering to :func:`maybe_render_classification`, and returns
    the resulting :class:`ClassificationReport` so callers can act on it
    (e.g. apply a policy gate).

    Args:
        args: Parsed CLI arguments.
        report: The audit report produced by the main scan pipeline.

    Returns:
        A :class:`ClassificationReport` when ``--classify`` was requested,
        otherwise ``None``.
    """
    if not getattr(args, "classify", False):
        return None

    classification = classify_report(report)
    maybe_render_classification(args, classification)
    return classification
