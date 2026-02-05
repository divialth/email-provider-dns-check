"""Stable public API for programmatic usage."""

from __future__ import annotations

from .dns_resolver import CachingResolver, DnsLookupError, DnsResolver
from .provider_config import (
    ProviderConfig,
    list_providers,
    load_provider_config,
    resolve_provider_config,
)
from .runner import (
    CheckRequest,
    CheckResult,
    DetectionRequest,
    DetectionResult,
    run_checks,
    run_detection,
)
from .status import ExitCodes, Status, exit_code_for_status

__all__ = [
    "CachingResolver",
    "CheckRequest",
    "CheckResult",
    "DetectionRequest",
    "DetectionResult",
    "DnsLookupError",
    "DnsResolver",
    "ExitCodes",
    "ProviderConfig",
    "Status",
    "exit_code_for_status",
    "list_providers",
    "load_provider_config",
    "resolve_provider_config",
    "run_checks",
    "run_detection",
]
