"""Regression tests for project version consistency."""

from __future__ import annotations

from pathlib import Path

import provider_check


def test_project_version_references_are_consistent() -> None:
    """Keep pyproject, source fallback, and README install tag in sync."""
    root = Path(__file__).resolve().parents[1]
    pyproject_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    source_version = provider_check._SOURCE_VERSION
    expected_line = f'version = "{source_version}"'
    assert expected_line in pyproject_text

    readme_text = (root / "README.md").read_text(encoding="utf-8")
    assert f"@v{source_version}" in readme_text

    assert provider_check.__version__ == source_version
