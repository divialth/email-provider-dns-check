"""Docstring coverage tests for source code."""

from __future__ import annotations

import ast
from pathlib import Path


def _missing_docstrings() -> list[tuple[Path, int, str, str]]:
    missing: list[tuple[Path, int, str, str]] = []
    for path in Path("src").rglob("*.py"):
        module = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                docstring = ast.get_docstring(node)
                missing.extend(
                    [] if docstring else [(path, node.lineno, node.__class__.__name__, node.name)]
                )
    return missing


def test_docstring_coverage() -> None:
    missing = _missing_docstrings()
    details = "\n".join(
        f"{path}:{lineno} {kind} {name}" for path, lineno, kind, name in sorted(missing)
    )
    assert not missing, f"Missing docstrings:\n{details}"
