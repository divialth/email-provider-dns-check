"""Email provider DNS checker package."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from . import api, runner

try:  # pragma: no cover - depends on installation metadata
    __version__ = version("email-provider-dns-check")
except PackageNotFoundError:  # pragma: no cover - fallback for source checkouts
    __version__ = "1.0.0"

__all__ = [
    "api",
    "checker",
    "dns_resolver",
    "provider_config",
    "runner",
    "__version__",
]
