"""Utilities for pinning dependencies to their latest resolved versions."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from dep_audit.resolver import ResolvedDep


def _pin_line(line: str, dep: ResolvedDep) -> str:
    """Return a requirements-style line pinned to dep.latest_version."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line
    # Replace any existing version specifier or add ==latest
    name_pattern = re.compile(r"^([A-Za-z0-9_\-\.]+)", re.IGNORECASE)
    m = name_pattern.match(stripped)
    if m and m.group(1).lower() == dep.name.lower() and dep.latest_version:
        return f"{dep.name}=={dep.latest_version}\n"
    return line


def pin_dependencies(
    deps: List[ResolvedDep],
    requirements_path: Path,
) -> List[Tuple[str, str]]:
    """Rewrite *requirements_path* so every dep in *deps* is pinned to latest.

    Returns a list of (package, new_version) tuples for changed lines.
    """
    if not requirements_path.exists():
        raise FileNotFoundError(f"{requirements_path} does not exist")

    lines = requirements_path.read_text().splitlines(keepends=True)
    dep_map = {d.name.lower(): d for d in deps if d.latest_version}

    new_lines: List[str] = []
    changes: List[Tuple[str, str]] = []

    for line in lines:
        stripped = line.strip()
        m = re.match(r"^([A-Za-z0-9_\-\.]+)", stripped)
        if m:
            key = m.group(1).lower()
            if key in dep_map:
                dep = dep_map[key]
                new_line = _pin_line(line, dep)
                if new_line != line:
                    changes.append((dep.name, dep.latest_version))  # type: ignore[arg-type]
                new_lines.append(new_line)
                continue
        new_lines.append(line)

    requirements_path.write_text("".join(new_lines))
    return changes


def pin_report(deps: List[ResolvedDep], requirements_path: Path) -> str:
    """Return a human-readable summary of pinning changes."""
    changes = pin_dependencies(deps, requirements_path)
    if not changes:
        return "No changes made."
    lines = [f"Pinned {len(changes)} package(s) in {requirements_path}:"]
    for name, version in changes:
        lines.append(f"  {name}=={version}")
    return "\n".join(lines)
