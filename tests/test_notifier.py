"""Tests for dep_audit.notifier."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.notifier import NotifyConfig, _build_payload, notify_webhook, notify_log_file, notify


def _dep(name="requests", current="2.0.0", latest="3.0.0", vulns=None):
    return ResolvedDep(
        name=name,
        current_version=current,
        latest_version=latest,
        vulnerabilities=vulns or [],
    )


@pytest.fixture
def report():
    fa = FileAudit(path="requirements.txt", deps=[_dep()])
    return AuditReport(file_audits=[fa])


def test_build_payload_keys(report):
    payload = _build_payload(report)
    assert "total_deps" in payload
    assert "outdated" in payload
    assert "vulnerable" in payload
    assert "issue_rate" in payload
    assert "files_with_issues" in payload


def test_build_payload_files_with_issues(report):
    payload = _build_payload(report)
    assert "requirements.txt" in payload["files_with_issues"]


def test_notify_webhook_returns_false_when_no_url(report):
    config = NotifyConfig(webhook_url=None)
    assert notify_webhook(report, config) is False


def test_notify_webhook_posts_payload(report):
    config = NotifyConfig(webhook_url="https://example.com/hook")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    with patch("dep_audit.notifier.requests.post", return_value=mock_resp) as mock_post:
        result = notify_webhook(report, config)
    assert result is True
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["json"]["total_deps"] >= 1


def test_notify_webhook_returns_false_below_min_issues():
    dep = _dep(current="1.0.0", latest="1.0.0")  # not outdated
    fa = FileAudit(path="requirements.txt", deps=[dep])
    report = AuditReport(file_audits=[fa])
    config = NotifyConfig(webhook_url="https://example.com/hook", min_issue_count=1)
    result = notify_webhook(report, config)
    assert result is False


def test_notify_webhook_returns_false_on_request_error(report):
    config = NotifyConfig(webhook_url="https://example.com/hook")
    with patch("dep_audit.notifier.requests.post", side_effect=Exception("err")):
        result = notify_webhook(report, config)
    assert result is False


def test_notify_log_file_writes_json(report, tmp_path):
    log = tmp_path / "audit.log"
    config = NotifyConfig(log_file=str(log))
    result = notify_log_file(report, config)
    assert result is True
    line = log.read_text().strip()
    data = json.loads(line)
    assert "total_deps" in data


def test_notify_log_file_returns_false_when_no_path(report):
    config = NotifyConfig(log_file=None)
    assert notify_log_file(report, config) is False


def test_notify_calls_both_channels(report, tmp_path):
    log = tmp_path / "audit.log"
    config = NotifyConfig(webhook_url="https://example.com/hook", log_file=str(log))
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    with patch("dep_audit.notifier.requests.post", return_value=mock_resp):
        notify(report, config)
    assert log.exists()
