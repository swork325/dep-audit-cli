"""Tests for dep_audit.profiler and dep_audit.cli_profile."""
from __future__ import annotations

import argparse
import json

import pytest

from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.resolver import ResolvedDep
from dep_audit.vulnerability import Vulnerability, VulnResult
from dep_audit.profiler import build_profiles, DepProfile
from dep_audit.cli_profile import add_profile_args, render_profiles, maybe_render_profiles


def _vuln(id_: str, severity: str = "high") -> Vulnerability:
    return Vulnerability(id=id_, description="desc", severity=severity, fix_version=None)


def _dep(name: str, current: str = "1.0.0", latest: str = "2.0.0",
         outdated: bool = True, vulns=None) -> ResolvedDep:
    vr = VulnResult(package=name, vulnerabilities=vulns or [])
    return ResolvedDep(
        name=name, current_version=current, latest_version=latest,
        is_outdated=outdated, vuln_result=vr,
    )


@pytest.fixture
def report():
    deps_a = [_dep("requests", vulns=[_vuln("CVE-1")]), _dep("flask", outdated=False)]
    deps_b = [_dep("requests", current="1.1.0")]
    return AuditReport(files=[
        FileAudit(path="a/requirements.txt", deps=deps_a),
        FileAudit(path="b/requirements.txt", deps=deps_b),
    ])


def test_build_profiles_keys(report):
    profiles = build_profiles(report)
    assert set(profiles.keys()) == {"requests", "flask"}


def test_requests_appears_in_two_files(report):
    profiles = build_profiles(report)
    assert len(profiles["requests"].files) == 2


def test_flask_appears_in_one_file(report):
    profiles = build_profiles(report)
    assert profiles["flask"].file_count == 1


def test_requests_aggregates_versions(report):
    profiles = build_profiles(report)
    assert set(profiles["requests"].current_versions) == {"1.0.0", "1.1.0"}


def test_vuln_deduplicated(report):
    # CVE-1 appears once even though requests is in two files
    profiles = build_profiles(report)
    assert profiles["requests"].vuln_count == 1


def test_highest_severity(report):
    profiles = build_profiles(report)
    assert profiles["requests"].highest_severity == "high"


def test_highest_severity_none_for_clean_dep(report):
    profiles = build_profiles(report)
    assert profiles["flask"].highest_severity is None


def test_render_profiles_text(report):
    output = render_profiles(report, fmt="text")
    assert "flask" in output
    assert "requests" in output
    assert "Outdated" in output


def test_render_profiles_json(report):
    output = render_profiles(report, fmt="json")
    data = json.loads(output)
    names = [d["name"] for d in data]
    assert "requests" in names


def test_maybe_render_profiles_returns_none_when_flag_off(report):
    args = argparse.Namespace(profile=False, profile_format="text")
    assert maybe_render_profiles(args, report) is None


def test_maybe_render_profiles_returns_string_when_flag_on(report):
    args = argparse.Namespace(profile=True, profile_format="text")
    result = maybe_render_profiles(args, report)
    assert isinstance(result, str) and len(result) > 0


def test_add_profile_args_defaults():
    parser = argparse.ArgumentParser()
    add_profile_args(parser)
    args = parser.parse_args([])
    assert args.profile is False
    assert args.profile_format == "text"
