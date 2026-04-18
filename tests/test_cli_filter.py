"""Tests for dep_audit.cli_filter."""
from __future__ import annotations

import argparse

from dep_audit.cli_filter import add_filter_args, filter_config_from_args
from dep_audit.filter import FilterConfig


def _parse(*args: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_filter_args(parser)
    return parser.parse_args(list(args))


def test_defaults():
    ns = _parse()
    cfg = filter_config_from_args(ns)
    assert cfg == FilterConfig()


def test_only_outdated_flag():
    ns = _parse("--only-outdated")
    cfg = filter_config_from_args(ns)
    assert cfg.only_outdated is True
    assert cfg.only_vulnerable is False


def test_only_vulnerable_flag():
    ns = _parse("--only-vulnerable")
    cfg = filter_config_from_args(ns)
    assert cfg.only_vulnerable is True


def test_min_severity():
    ns = _parse("--min-severity", "high")
    cfg = filter_config_from_args(ns)
    assert cfg.min_severity == "high"


def test_package_glob():
    ns = _parse("--package", "django*")
    cfg = filter_config_from_args(ns)
    assert cfg.package_glob == "django*"


def test_path_glob():
    ns = _parse("--path", "**/dev*")
    cfg = filter_config_from_args(ns)
    assert cfg.path_glob == "**/dev*"


def test_invalid_severity_raises(capsys):
    import pytest
    with pytest.raises(SystemExit):
        _parse("--min-severity", "extreme")
