"""Tests for dep_audit.cli_recommend."""
import argparse
import pytest
from dep_audit.recommender import Recommendation
from dep_audit.cli_recommend import (
    add_recommend_args,
    filter_recommendations,
    render_recommendations,
    maybe_render_recommendations,
)


def _parse(*args):
    p = argparse.ArgumentParser()
    add_recommend_args(p)
    return p.parse_args(list(args))


def _rec(pkg, action="upgrade"):
    return Recommendation(
        package=pkg,
        current_version="1.0",
        latest_version="2.0",
        action=action,
        reason="test reason",
    )


def test_defaults():
    args = _parse()
    assert args.recommend is False
    assert args.recommend_action is None


def test_recommend_flag():
    args = _parse("--recommend")
    assert args.recommend is True


def test_recommend_action_flag():
    args = _parse("--recommend-action", "upgrade")
    assert args.recommend_action == "upgrade"


def test_filter_recommendations_none_returns_all():
    recs = [_rec("flask"), _rec("requests", "review_vulns")]
    assert filter_recommendations(recs, None) == recs


def test_filter_recommendations_by_action():
    recs = [_rec("flask", "upgrade"), _rec("urllib3", "review_vulns")]
    result = filter_recommendations(recs, "upgrade")
    assert len(result) == 1
    assert result[0].package == "flask"


def test_render_recommendations_empty():
    out = render_recommendations([])
    assert "good" in out


def test_render_recommendations_shows_package():
    recs = [_rec("flask", "upgrade")]
    out = render_recommendations(recs)
    assert "flask" in out
    assert "1.0" in out
    assert "2.0" in out


def test_maybe_render_skips_when_flag_off(capsys):
    args = _parse()
    maybe_render_recommendations(args, [_rec("flask")])
    captured = capsys.readouterr()
    assert captured.out == ""


def test_maybe_render_prints_when_flag_on(capsys):
    args = _parse("--recommend")
    maybe_render_recommendations(args, [_rec("flask")])
    captured = capsys.readouterr()
    assert "flask" in captured.out
