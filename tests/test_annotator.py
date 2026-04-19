"""Tests for dep_audit.annotator."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.resolver import ResolvedDep
from dep_audit.annotator import (
    _age_label,
    fetch_publish_date,
    annotate_dep,
    annotate_all,
    AnnotatedDep,
)


def _dep(name="requests", current="2.28.0", latest="2.31.0") -> ResolvedDep:
    return ResolvedDep(name=name, current_version=current, latest_version=latest, outdated=current != latest)


def _mock_session(upload_time: str | None):
    session = MagicMock()
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    if upload_time is not None:
        resp.json.return_value = {"urls": [{"upload_time_iso_8601": upload_time}]}
    else:
        resp.json.return_value = {"urls": []}
    session.get.return_value = resp
    return session


@pytest.mark.parametrize("days,expected", [
    (0, "fresh"),
    (29, "fresh"),
    (30, "recent"),
    (179, "recent"),
    (180, "aging"),
    (364, "aging"),
    (365, "stale"),
    (1000, "stale"),
])
def test_age_label(days, expected):
    assert _age_label(days) == expected


def test_fetch_publish_date_returns_datetime():
    ts = "2023-01-15T10:00:00Z"
    session = _mock_session(ts)
    result = fetch_publish_date("requests", "2.28.0", session=session)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_fetch_publish_date_returns_none_on_empty_urls():
    session = _mock_session(None)
    result = fetch_publish_date("requests", "2.28.0", session=session)
    assert result is None


def test_fetch_publish_date_returns_none_on_http_error():
    session = MagicMock()
    session.get.side_effect = Exception("network error")
    result = fetch_publish_date("requests", "2.28.0", session=session)
    assert result is None


def test_fetch_publish_date_hits_correct_url():
    session = _mock_session("2022-06-01T00:00:00Z")
    fetch_publish_date("flask", "2.0.0", session=session)
    session.get.assert_called_once_with("https://pypi.org/pypi/flask/2.0.0/json", timeout=10)


def test_annotate_dep_no_version_returns_unknown():
    dep = ResolvedDep(name="pkg", current_version=None, latest_version=None, outdated=False)
    result = annotate_dep(dep)
    assert result.age_label == "unknown"
    assert result.age_days is None


def test_annotate_dep_computes_age():
    old_date = (datetime.now(tz=timezone.utc) - timedelta(days=400)).isoformat()
    session = _mock_session(old_date)
    dep = _dep()
    result = annotate_dep(dep, session=session)
    assert result.age_label == "stale"
    assert result.age_days >= 400


def test_annotate_all_returns_list_of_correct_length():
    session = _mock_session("2023-03-01T00:00:00Z")
    deps = [_dep("requests"), _dep("flask")]
    results = annotate_all(deps, session=session)
    assert len(results) == 2
    assert all(isinstance(r, AnnotatedDep) for r in results)
