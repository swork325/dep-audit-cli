"""Discover requirements files across one or more project directories."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

# Filenames recognised as dependency manifests
REQUIREMENTS_PATTERNS: list[str] = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "requirements/*.txt",
]

PYPROJECT_TOML = "pyproject.toml"
SETUP_CFG = "setup.cfg"
SETUP_PY = "setup.py"


def _iter_requirements_txt(root: Path) -> Iterator[Path]:
    """Yield every requirements *.txt file under *root*."""
    for pattern in REQUIREMENTS_PATTERNS:
        yield from root.glob(pattern)


def find_dependency_files(directories: list[str | Path]) -> dict[str, list[Path]]:
    """
    Scan each directory for dependency manifests.

    Returns a mapping of ``str(directory)`` -> list of discovered manifest paths.
    """
    results: dict[str, list[Path]] = {}

    for raw in directories:
        root = Path(raw).expanduser().resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"Not a directory: {root}")

        found: list[Path] = []

        # requirements txt variants
        for p in _iter_requirements_txt(root):
            if p.is_file():
                found.append(p)

        # pyproject.toml / setup.cfg / setup.py at the root level
        for name in (PYPROJECT_TOML, SETUP_CFG, SETUP_PY):
            candidate = root / name
            if candidate.is_file():
                found.append(candidate)

        # Deduplicate while preserving order
        seen: set[Path] = set()
        unique: list[Path] = []
        for p in found:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        results[str(root)] = unique

    return results
