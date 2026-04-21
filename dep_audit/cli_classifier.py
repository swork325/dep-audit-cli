"""CLI integration for the dependency risk classifier."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from dep_audit.auditor import AuditReport
from dep_audit.classifier import ClassificationReport, RiskTier, classify_report

_TIER_ORDER = [
    RiskTier.CRITICAL,
    RiskTier.HIGH,
    RiskTier.MEDIUM,
    RiskTier.LOW,
    RiskTier.CLEAN,
]


def add_classifier_args(parser: argparse.ArgumentParser) -> None:
    grp = parser.add_argument_group("risk classification")
    grp.add_argument(
        "--classify",
        action="store_true",
        default=False,
        help="Show a risk-tier breakdown of all dependencies.",
    )
    grp.add_argument(
        "--classify-format",
        choices=["text", "json"],
        default="text",
        dest="classify_format",
        help="Output format for the classification report (default: text).",
    )
    grp.add_argument(
        "--min-tier",
        choices=[t.value for t in RiskTier],
        default=None,
        dest="min_tier",
        help="Only show dependencies at or above this risk tier.",
    )


def _render_text(
    cr: ClassificationReport, min_tier: Optional[RiskTier] = None
) -> str:
    lines = ["Risk Classification Report", "=" * 28]
    for tier in _TIER_ORDER:
        if min_tier and _TIER_ORDER.index(tier) > _TIER_ORDER.index(min_tier):
            continue
        deps = cr.by_tier(tier)
        lines.append(f"\n[{tier.value.upper()}] ({len(deps)} deps)")
        for cd in deps:
            reasons = ", ".join(cd.reasons)
            lines.append(f"  {cd.dep.name}=={cd.dep.installed_version}  — {reasons}")
    return "\n".join(lines)


def _render_json(cr: ClassificationReport, min_tier: Optional[RiskTier] = None) -> str:
    out = {}
    for tier in _TIER_ORDER:
        if min_tier and _TIER_ORDER.index(tier) > _TIER_ORDER.index(min_tier):
            continue
        out[tier.value] = [
            {"name": cd.dep.name, "version": cd.dep.installed_version, "reasons": cd.reasons}
            for cd in cr.by_tier(tier)
        ]
    return json.dumps(out, indent=2)


def maybe_render_classification(
    args: argparse.Namespace, report: AuditReport
) -> None:
    if not getattr(args, "classify", False):
        return
    cr = classify_report(report)
    min_tier = RiskTier(args.min_tier) if args.min_tier else None
    if args.classify_format == "json":
        print(_render_json(cr, min_tier))
    else:
        print(_render_text(cr, min_tier))
