"""Tests for dep_audit.finder — dependency file discovery."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from dep_audit.finder import find_dependency_files


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    """Create a minimal fake project layout."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==7.4.0\n")
    req_dir = tmp_path / "requirements"
    req_dir.mkdir()
    (req_dir / "base.txt").write_text("flask==3.0.0\n")
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent("""
            [project]
            name = "demo"
            dependencies = ["httpx>=0.27"]
        """)
    )
    return tmp_path


def test_finds_requirements_txt(project_dir: Path) -> None:
    result = find_dependency_files([project_dir])
    paths = result[str(project_dir)]
    names = [p.name for p in paths]
    assert "requirements.txt" in names


def test_finds_requirements_dev(project_dir: Path) -> None:
    result = find_dependency_files([project_dir])
    paths = result[str(project_dir)]
    names = [p.name for p in paths]
    assert "requirements-dev.txt" in names


def test_finds_nested_requirements(project_dir: Path) -> None:
    result = find_dependency_files([project_dir])
    paths = result[str(project_dir)]
    assert any("requirements" in str(p) and p.name == "base.txt" for p in paths)


def test_finds_pyproject_toml(project_dir: Path) -> None:
    result = find_dependency_files([project_dir])
    paths = result[str(project_dir)]
    names = [p.name for p in paths]
    assert "pyproject.toml" in names


def test_no_duplicates(project_dir: Path) -> None:
    result = find_dependency_files([project_dir])
    paths = result[str(project_dir)]
    assert len(paths) == len(set(paths))


def test_raises_for_missing_directory(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent"
    with pytest.raises(NotADirectoryError):
        find_dependency_files([missing])


def test_empty_directory(tmp_path: Path) -> None:
    result = find_dependency_files([tmp_path])
    assert result[str(tmp_path)] == []
