"""Email provider DNS checker package."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from . import api, runner

_SOURCE_VERSION = "1.1.1"


def _is_source_checkout(module_path: Path) -> bool:
    """Return whether the package is imported from a source checkout.

    Args:
        module_path (Path): Path to this module file.

    Returns:
        bool: True when loaded from a ``src/`` layout checkout.
    """
    return module_path.resolve().parents[1].name == "src"


def _resolve_version() -> str:
    """Resolve package version for both installs and source checkouts.

    Returns:
        str: Version string.
    """
    if _is_source_checkout(Path(__file__)):
        return _SOURCE_VERSION
    try:  # pragma: no cover - depends on installation metadata
        return version("email-provider-dns-check")
    except PackageNotFoundError:  # pragma: no cover - fallback for unusual environments
        return _SOURCE_VERSION


__version__ = _resolve_version()

__all__ = [
    "api",
    "checker",
    "dns_resolver",
    "provider_config",
    "runner",
    "__version__",
]
