"""Simple periodic scheduler to re-run audits and fire notifications."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScheduleConfig:
    roots: List[str]
    interval_seconds: int = 3600
    max_runs: Optional[int] = None


def _single_run(roots: List[str], on_report: Callable) -> None:
    from dep_audit.finder import find_dependency_files
    from dep_audit.auditor import AuditReport, FileAudit
    from dep_audit.resolver import resolve_dependencies

    file_audits = []
    for root in roots:
        for dep_file in find_dependency_files(Path(root)):
            deps = resolve_dependencies(dep_file)
            file_audits.append(FileAudit(path=str(dep_file), deps=deps))

    report = AuditReport(file_audits=file_audits)
    on_report(report)


def run_scheduler(
    config: ScheduleConfig,
    on_report: Callable,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Run audit loop. Calls on_report(AuditReport) after each scan."""
    runs = 0
    while True:
        logger.info("Scheduler: starting audit run %d", runs + 1)
        try:
            _single_run(config.roots, on_report)
        except Exception as exc:  # noqa: BLE001
            logger.error("Audit run failed: %s", exc)
        runs += 1
        if config.max_runs is not None and runs >= config.max_runs:
            break
        sleep_fn(config.interval_seconds)
