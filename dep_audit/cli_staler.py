"""CLI integration for staleness reporting."""
from __future__ import annotations

import argparse
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.annotator import fetch_publish_date
from dep_audit.resolver import ResolvedDep
from dep_audit.staler import StalenessReport, build_staleness_report


def add_staler_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("staleness")
    grp.add_argument(
        "--show-stale",
        action="store_true",
        default=False,
        help="Show deps whose latest release is older than --stale-days.",
    )
    grp.add_argument(
        "--stale-days",
        type=int,
        default=365,
        metavar="N",
        help="Number of days without a new release to consider a dep stale (default: 365).",
    )


def _collect_deps(report: AuditReport) -> list:
    seen: dict = {}
    for fa in report.files:
        for dep in fa.deps:
            if dep.name not in seen:
                seen[dep.name] = dep
    return list(seen.values())


def render_staleness(sr: StalenessReport) -> str:
    lines = [f"Staleness report  (threshold: {sr.stale[0].threshold_days if sr.stale else '?'} days)"]
    lines.append(f"  Stale: {sr.stale_count}/{sr.total}  ({sr.stale_rate:.0%})")
    if sr.stale:
        lines.append("  Stale packages:")
        for sd in sorted(sr.stale, key=lambda s: -s.days_since_release):
            lines.append(f"    {sd.dep.name}=={sd.dep.current or '?'}  ({sd.days_since_release}d since last release)")
    return "\n".join(lines)


def maybe_render_staleness(
    args: argparse.Namespace,
    report: AuditReport,
    session=None,
) -> Optional[StalenessReport]:
    if not getattr(args, "show_stale", False):
        return None

    deps = _collect_deps(report)
    publish_dates = {}
    for dep in deps:
        publish_dates[dep.name] = fetch_publish_date(dep, session=session)

    threshold = getattr(args, "stale_days", 365)
    sr = build_staleness_report(deps, publish_dates, threshold_days=threshold)
    print(render_staleness(sr))
    return sr
