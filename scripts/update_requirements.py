"""Generate requirements files from pyproject.toml."""

from __future__ import annotations

from pathlib import Path
import tomllib


def _load_pyproject(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _write_requirements(path: Path, deps: list[str], header: str) -> None:
    lines = [header, ""]
    lines.extend(deps)
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    data = _load_pyproject(pyproject)

    project = data.get("project", {})
    deps = project.get("dependencies", [])
    optional = project.get("optional-dependencies", {})
    test_deps = optional.get("test", [])

    _write_requirements(
        root / "requirements.txt",
        deps,
        "# Auto-generated from pyproject.toml via scripts/update_requirements.py",
    )
    _write_requirements(
        root / "requirements-dev.txt",
        deps + test_deps,
        "# Auto-generated from pyproject.toml via scripts/update_requirements.py",
    )


if __name__ == "__main__":
    main()
