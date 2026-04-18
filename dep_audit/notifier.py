"""Notification hooks for audit results (stdout, file, webhook)."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import requests

from dep_audit.auditor import AuditReport

logger = logging.getLogger(__name__)


@dataclass
class NotifyConfig:
    webhook_url: Optional[str] = None
    log_file: Optional[str] = None
    min_issue_count: int = 1


def _build_payload(report: AuditReport) -> dict:
    from dep_audit.reporter import compute_stats
    stats = compute_stats(report)
    return {
        "total_deps": stats.total_deps,
        "outdated": stats.total_outdated,
        "vulnerable": stats.total_vulnerable,
        "issue_rate": stats.issue_rate,
        "files_with_issues": [
            fa.path for fa in report.file_audits if fa.has_issues
        ],
    }


def notify_webhook(report: AuditReport, config: NotifyConfig) -> bool:
    """POST summary payload to webhook. Returns True on success."""
    if not config.webhook_url:
        return False
    from dep_audit.reporter import compute_stats
    stats = compute_stats(report)
    if (stats.total_outdated + stats.total_vulnerable) < config.min_issue_count:
        return False
    payload = _build_payload(report)
    try:
        resp = requests.post(config.webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Webhook notification failed: %s", exc)
        return False


def notify_log_file(report: AuditReport, config: NotifyConfig) -> bool:
    """Append JSON summary to a log file. Returns True on success."""
    if not config.log_file:
        return False
    payload = _build_payload(report)
    try:
        with open(config.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
        return True
    except OSError as exc:
        logger.warning("Log file notification failed: %s", exc)
        return False


def notify(report: AuditReport, config: NotifyConfig) -> None:
    """Run all configured notification channels."""
    notify_webhook(report, config)
    notify_log_file(report, config)
