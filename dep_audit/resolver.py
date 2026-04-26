"""Resolve installed versions and latest available versions for dependencies."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import requests

PYPI_URL = "https://pypi.org/pypi/{package}/json"


@dataclass
class ResolvedDep:
    name: str
    required_specifier: str
    installed_version: Optional[str]
    latest_version: Optional[str]

    @property
    def is_outdated(self) -> bool:
        if self.installed_version is None or self.latest_version is None:
            return False
        return self.installed_version != self.latest_version


def _normalize(name: str) -> str:
    """Normalize a package name per PEP 503 (replace runs of [-_.] with '-' and lowercase)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_latest_version(package: str, session: Optional[requests.Session] = None) -> Optional[str]:
    """Return the latest version string from PyPI, or None on failure."""
    client = session or requests.Session()
    try:
        resp = client.get(PYPI_URL.format(package=_normalize(package)), timeout=5)
        resp.raise_for_status()
        return resp.json()["info"]["version"]
    except requests.HTTPError as exc:
        # Surface 404s distinctly so callers can tell apart "not found" from network errors.
        if exc.response is not None and exc.response.status_code == 404:
            return None
        return None
    except Exception:
        return None


def resolve_dependencies(
    requirements: list[dict[str, str]],
    session: Optional[requests.Session] = None,
) -> list[ResolvedDep]:
    """Given a list of {name, specifier} dicts, resolve installed + latest versions.

    Args:
        requirements: list of dicts with keys 'name' and 'specifier'.
        session: optional requests.Session for HTTP calls.

    Returns:
        List of ResolvedDep instances.
    """
    import importlib.metadata as meta

    resolved: list[ResolvedDep] = []
    client = session or requests.Session()

    for req in requirements:
        name = req["name"]
        specifier = req.get("specifier", "")

        try:
            installed = meta.version(name)
        except meta.PackageNotFoundError:
            installed = None

        latest = fetch_latest_version(name, session=client)

        resolved.append(
            ResolvedDep(
                name=name,
                required_specifier=specifier,
                installed_version=installed,
                latest_version=latest,
            )
        )

    return resolved
