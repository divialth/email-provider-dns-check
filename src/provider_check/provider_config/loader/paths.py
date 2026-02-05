"""Provider config path helpers."""

from __future__ import annotations

from importlib import resources
from importlib.resources import abc as resources_abc
from pathlib import Path
from typing import Iterable, List

from ..utils import PROVIDER_DIR_NAME, PROVIDER_PACKAGE, external_config_dirs


def _normalize_provider_dirs(provider_dirs: Iterable[Path | str] | None) -> List[Path]:
    """Normalize provider directory inputs.

    Args:
        provider_dirs (Iterable[Path | str] | None): Provider directory inputs.

    Returns:
        List[Path]: Normalized provider directories with duplicates removed.
    """
    normalized: List[Path] = []
    seen: set[str] = set()
    for entry in provider_dirs or []:
        path = Path(entry).expanduser()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(path)
    return normalized


def _external_provider_dirs(provider_dirs: Iterable[Path | str] | None = None) -> List[Path]:
    """Return directories to search for provider config files.

    Args:
        provider_dirs (Iterable[Path | str] | None): Additional provider directories.

    Returns:
        List[Path]: Provider directories derived from config roots.
    """
    custom_dirs = _normalize_provider_dirs(provider_dirs)
    default_dirs = [path / PROVIDER_DIR_NAME for path in external_config_dirs()]
    return [*custom_dirs, *default_dirs]


def _iter_provider_paths_in_dir(path: Path) -> Iterable[Path]:
    """Iterate YAML provider files in a directory.

    Args:
        path (Path): Directory to search.

    Yields:
        Path: Provider config file paths.
    """
    if not path.is_dir():
        return
    for entry in sorted(path.iterdir(), key=lambda item: item.name):
        if entry.is_file() and entry.suffix in {".yaml", ".yml"}:
            yield entry


def _iter_packaged_paths() -> Iterable[resources_abc.Traversable]:
    """Iterate packaged provider config files.

    Yields:
        resources_abc.Traversable: Packaged provider config file paths.
    """
    base = resources.files(PROVIDER_PACKAGE)
    entries = [entry for entry in base.iterdir() if entry.is_file()]
    for entry in sorted(entries, key=lambda item: item.name):
        if entry.suffix in {".yaml", ".yml"}:
            yield entry


def _iter_provider_paths(provider_dirs: Iterable[Path | str] | None = None) -> Iterable[object]:
    """Iterate all provider config file paths.

    Args:
        provider_dirs (Iterable[Path | str] | None): Additional provider directories.

    Yields:
        object: Provider config file paths from external and packaged sources.
    """
    from . import _external_provider_dirs

    if provider_dirs is None:
        directories = _external_provider_dirs()
    else:
        directories = _external_provider_dirs(provider_dirs)
    for directory in directories:
        yield from _iter_provider_paths_in_dir(directory)
    yield from _iter_packaged_paths()
