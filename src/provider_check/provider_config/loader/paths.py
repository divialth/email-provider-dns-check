"""Provider config path helpers."""

from __future__ import annotations

from importlib import resources
from importlib.resources import abc as resources_abc
from pathlib import Path
from typing import Iterable, List

from ..utils import PROVIDER_DIR_NAME, PROVIDER_PACKAGE, external_config_dirs


def _external_provider_dirs() -> List[Path]:
    """Return directories to search for provider config files.

    Returns:
        List[Path]: Provider directories derived from config roots.
    """
    return [path / PROVIDER_DIR_NAME for path in external_config_dirs()]


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


def _iter_provider_paths() -> Iterable[object]:
    """Iterate all provider config file paths.

    Yields:
        object: Provider config file paths from external and packaged sources.
    """
    from . import _external_provider_dirs

    for directory in _external_provider_dirs():
        yield from _iter_provider_paths_in_dir(directory)
    yield from _iter_packaged_paths()
