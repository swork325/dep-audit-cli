"""Tests for dep_audit.scheduler."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dep_audit.scheduler import ScheduleConfig, run_scheduler, _single_run


def test_schedule_config_defaults():
    cfg = ScheduleConfig(roots=["/tmp"])
    assert cfg.interval_seconds == 3600
    assert cfg.max_runs is None


def test_run_scheduler_calls_on_report_once():
    cfg = ScheduleConfig(roots=["/tmp"], max_runs=1)
    callback = MagicMock()
    sleep_fn = MagicMock()
    with patch("dep_audit.scheduler._single_run") as mock_run:
        run_scheduler(cfg, callback, sleep_fn=sleep_fn)
    mock_run.assert_called_once_with(["/tmp"], callback)
    sleep_fn.assert_not_called()


def test_run_scheduler_sleeps_between_runs():
    cfg = ScheduleConfig(roots=["/tmp"], interval_seconds=60, max_runs=2)
    callback = MagicMock()
    sleep_fn = MagicMock()
    with patch("dep_audit.scheduler._single_run"):
        run_scheduler(cfg, callback, sleep_fn=sleep_fn)
    sleep_fn.assert_called_once_with(60)


def test_run_scheduler_continues_on_error():
    cfg = ScheduleConfig(roots=["/tmp"], max_runs=2)
    callback = MagicMock()
    sleep_fn = MagicMock()
    with patch("dep_audit.scheduler._single_run", side_effect=RuntimeError("boom")):
        run_scheduler(cfg, callback, sleep_fn=sleep_fn)  # should not raise
    assert sleep_fn.call_count == 1


def test_single_run_builds_report(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    callback = MagicMock()
    with patch("dep_audit.scheduler.resolve_dependencies", return_value=[]) as mock_res:
        _single_run([str(tmp_path)], callback)
    callback.assert_called_once()
    report = callback.call_args[0][0]
    assert len(report.file_audits) == 1
    assert "requirements.txt" in report.file_audits[0].path
