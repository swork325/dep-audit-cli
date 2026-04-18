"""Helpers to build a FilterConfig from CLI arguments."""
from __future__ import annotations

import argparse

from dep_audit.filter import FilterConfig

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


def add_filter_args(parser: argparse.ArgumentParser) -> None:
    """Attach filter-related flags to *parser*."""
    grp = parser.add_argument_group("filtering")
    grp.add_argument(
        "--only-outdated",
        action="store_true",
        default=False,
        help="Show only outdated dependencies.",
    )
    grp.add_argument(
        "--only-vulnerable",
        action="store_true",
        default=False,
        help="Show only dependencies with known vulnerabilities.",
    )
    grp.add_argument(
        "--min-severity",
        choices=_VALID_SEVERITIES,
        default=None,
        metavar="LEVEL",
        help="Minimum vulnerability severity to include (low/medium/high/critical).",
    )
    grp.add_argument(
        "--package",
        dest="package_glob",
        default=None,
        metavar="GLOB",
        help="Glob pattern to filter by package name (e.g. 'django*').",
    )
    grp.add_argument(
        "--path",
        dest="path_glob",
        default=None,
        metavar="GLOB",
        help="Glob pattern to filter by dependency file path.",
    )


def filter_config_from_args(args: argparse.Namespace) -> FilterConfig:
    """Build a :class:`FilterConfig` from parsed CLI *args*."""
    return FilterConfig(
        only_outdated=args.only_outdated,
        only_vulnerable=args.only_vulnerable,
        min_severity=args.min_severity,
        package_glob=args.package_glob,
        path_glob=args.path_glob,
    )
