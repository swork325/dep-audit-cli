"""Fetch and surface package changelog / release notes URLs for resolved deps."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import requests

from dep_audit.auditor import AuditReport
from dep_audit.resolver import ResolvedDep

_PYPI_URL = "https://pypi.org/pypi/{name}/json"

_LINK_KEYS = (
    "Changelog",
    "Change log",
    "Release notes",
    "Changes",
)


@dataclass
class ChangelogEntry:
    package: str
    version: str
    url: Optional[str] = None

    @property
    def has_url(self) -> bool:
        return self.url is not None


def _extract_changelog_url(info: dict) -> Optional[str]:
    """Return the first project-URL that looks like a changelog, or None."""
    project_urls: dict = info.get("project_urls") or {}
    for key, url in project_urls.items():
        if any(label.lower() in key.lower() for label in _LINK_KEYS):
            return url
    return None


def fetch_changelog_url(
    name: str,
    *,
    session: Optional[requests.Session] = None,
) -> Optional[str]:
    """Hit PyPI JSON API and return a changelog URL for *name*, or None."""
    sess = session or requests.Session()
    try:
        resp = sess.get(_PYPI_URL.format(name=name), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return _extract_changelog_url(data.get("info", {}))
    except Exception:
        return None


def build_changelog_entries(
    report: AuditReport,
    *,
    outdated_only: bool = True,
    session: Optional[requests.Session] = None,
) -> list[ChangelogEntry]:
    """Return one ChangelogEntry per unique package in *report*.

    When *outdated_only* is True (default) only packages flagged as outdated
    are included, since those are the ones users are most likely to want
    release-notes for.
    """
    seen: set[str] = set()
    entries: list[ChangelogEntry] = []

    for file_audit in report.files:
        for dep in file_audit.deps:
            if outdated_only and not dep.outdated:
                continue
            key = dep.name.lower()
            if key in seen:
                continue
            seen.add(key)
            url = fetch_changelog_url(dep.name, session=session)
            entries.append(
                ChangelogEntry(package=dep.name, version=dep.latest or dep.current, url=url)
            )

    return entries
