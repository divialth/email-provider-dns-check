"""Packaging layout regression tests."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_setuptools_package_dir_uses_src_layout() -> None:
    """Ensure setuptools is configured to install packages from src/ only."""
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    setuptools = data.get("tool", {}).get("setuptools", {})
    assert setuptools.get("package-dir") == {"": "src"}


def test_setuptools_find_packages_scans_src_only() -> None:
    """Ensure package discovery is scoped to src/ to avoid build dir leakage."""
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    packages_find = data.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    assert packages_find.get("where") == ["src"]
