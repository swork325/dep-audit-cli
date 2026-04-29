"""Extra metadata enrichment for audited dependencies.

Provides utilities to attach supplementary information to resolved
dependencies — such as download statistics, GitHub star counts, and
maintainer activity signals — so that downstream consumers (scorers,
classifiers, etc.) have richer data to work with.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import logging

import requests

from dep_audit.resolver import ResolvedDep

logger = logging.getLogger(__name__)

_PYPI_URL = "https://pypi.org/pypi/{name}/json"


@dataclass
class ExtrasInfo:
    """Supplementary metadata for a single dependency."""

    name: str
    # Monthly download estimate from PyPI stats (may be None if unavailable)
    monthly_downloads: Optional[int] = None
    # Number of open GitHub issues scraped from PyPI project_urls (best-effort)
    home_page: Optional[str] = None
    # Whether the package has been marked as yanked on its latest release
    yanked: bool = False
    # Requires-Python specifier declared by the package
    requires_python: Optional[str] = None
    # Raw classifiers list (e.g. 'Development Status :: 5 - Production/Stable')
    classifiers: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #

    @property
    def is_stable(self) -> bool:
        """Return True if any Development Status classifier indicates stable."""
        stable_markers = ("5 - production", "6 - mature")
        for cls in self.classifiers:
            lower = cls.lower()
            if "development status" in lower:
                if any(m in lower for m in stable_markers):
                    return True
        return False

    @property
    def is_deprecated(self) -> bool:
        """Return True if a classifier signals the package is inactive."""
        inactive_markers = ("7 - inactive", "inactive")
        for cls in self.classifiers:
            lower = cls.lower()
            if any(m in lower for m in inactive_markers):
                return True
        return False


def fetch_extras(
    dep: ResolvedDep,
    session: Optional[requests.Session] = None,
    timeout: int = 10,
) -> ExtrasInfo:
    """Fetch supplementary PyPI metadata for *dep*.

    Returns an :class:`ExtrasInfo` populated from the PyPI JSON API.  On any
    network or parsing error the function returns a minimal :class:`ExtrasInfo`
    with only the package name set, so callers never have to deal with ``None``.

    Args:
        dep: The resolved dependency whose extras should be fetched.
        session: Optional :class:`requests.Session` to reuse (useful for
            testing and connection pooling).
        timeout: HTTP request timeout in seconds.
    """
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    try:
        url = _PYPI_URL.format(name=dep.name)
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("fetch_extras failed for %s: %s", dep.name, exc)
        return ExtrasInfo(name=dep.name)
    finally:
        if close_session:
            session.close()

    info = data.get("info", {})
    releases = data.get("releases", {})

    # Determine whether the *current* pinned version is yanked.
    yanked = False
    if dep.current_version and dep.current_version in releases:
        files = releases[dep.current_version]
        yanked = all(f.get("yanked", False) for f in files) if files else False

    return ExtrasInfo(
        name=dep.name,
        home_page=info.get("home_page") or info.get("project_url"),
        yanked=yanked,
        requires_python=info.get("requires_python"),
        classifiers=info.get("classifiers") or [],
    )


def enrich_deps(
    deps: list[ResolvedDep],
    session: Optional[requests.Session] = None,
    timeout: int = 10,
) -> dict[str, ExtrasInfo]:
    """Fetch :class:`ExtrasInfo` for every dependency in *deps*.

    Deduplicates by normalised package name so that a package appearing in
    multiple requirement files is only fetched once.

    Returns:
        A mapping of normalised package name → :class:`ExtrasInfo`.
    """
    seen: dict[str, ExtrasInfo] = {}
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    try:
        for dep in deps:
            key = dep.name.lower().replace("-", "_")
            if key not in seen:
                seen[key] = fetch_extras(dep, session=session, timeout=timeout)
    finally:
        if close_session:
            session.close()

    return seen
