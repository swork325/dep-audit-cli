"""Compare resolved dependencies against a pinned environment file (e.g. pip freeze output)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from dep_audit.resolver import ResolvedDep
from dep_audit.auditor import AuditReport


@dataclass
class EnvMismatch:
    name: str
    required_version: Optional[str]   # version declared in requirements / pyproject
    env_version: Optional[str]         # version found in the env file
    missing_from_env: bool = False
    missing_from_report: bool = False

    @property
    def has_conflict(self) -> bool:
        if self.missing_from_env or self.missing_from_report:
            return True
        if self.required_version and self.env_version:
            return self.required_version.strip() != self.env_version.strip()
        return False


@dataclass
class EnvAuditResult:
    mismatches: List[EnvMismatch] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.mismatches)

    @property
    def conflicts(self) -> List[EnvMismatch]:
        return [m for m in self.mismatches if m.has_conflict]

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts)


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse a pip-freeze-style file into {normalised_name: version}."""
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
            env[name.strip().lower().replace("-", "_")] = version.strip()
    return env


def compare_with_env(report: AuditReport, env_path: Path) -> EnvAuditResult:
    """Cross-reference every resolved dep in *report* against *env_path*."""
    env = parse_env_file(env_path)
    result = EnvAuditResult()

    seen: set[str] = set()
    for file_audit in report.files:
        for dep in file_audit.deps:
            key = dep.name.lower().replace("-", "_")
            if key in seen:
                continue
            seen.add(key)
            env_ver = env.get(key)
            mismatch = EnvMismatch(
                name=dep.name,
                required_version=dep.current_version,
                env_version=env_ver,
                missing_from_env=env_ver is None,
            )
            if mismatch.has_conflict:
                result.mismatches.append(mismatch)

    for env_name, env_ver in env.items():
        if env_name not in seen:
            result.mismatches.append(
                EnvMismatch(
                    name=env_name,
                    required_version=None,
                    env_version=env_ver,
                    missing_from_report=True,
                )
            )

    return result
