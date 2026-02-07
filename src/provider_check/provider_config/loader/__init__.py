"""Load provider DNS validation configuration from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

from ..models import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    PTRConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    SRVConfig,
    SRVRecord,
    TLSAConfig,
    TLSARecord,
    TXTConfig,
)
from ..utils import (
    LOGGER,
    CONFIG_DIR_NAME,
    PROVIDER_DIR_NAME,
    PROVIDER_PACKAGE,
    _RESERVED_VARIABLES,
    _merge_provider_data,
    _normalize_extends,
    _normalize_key,
    _require_list,
    _require_mapping,
    _require_variables,
    external_config_dirs,
)
from .data import _is_enabled, _load_provider_data_map, _load_yaml, _resolve_provider_data
from .parse import _load_provider_from_data
from .paths import (
    _external_provider_dirs,
    _iter_packaged_paths,
    _iter_provider_paths,
    _iter_provider_paths_in_dir,
)


def load_provider_config_data(
    selection: str, provider_dirs: Iterable[Path | str] | None = None
) -> tuple[ProviderConfig, dict]:
    """Load a provider config and its resolved data mapping.

    Args:
        selection (str): Provider ID or name.
        provider_dirs (Iterable[Path | str] | None): Additional provider directories.

    Returns:
        tuple[ProviderConfig, dict]: Provider config and resolved data mapping.

    Raises:
        ValueError: If the provider is unknown or disabled.
    """
    if provider_dirs is None:
        provider = load_provider_config(selection)
        data_map = _load_provider_data_map()
    else:
        provider = load_provider_config(selection, provider_dirs=provider_dirs)
        data_map = _load_provider_data_map(provider_dirs=provider_dirs)
    cache: Dict[str, dict] = {}
    if provider.provider_id not in data_map:
        raise ValueError(f"Provider config source not found for '{provider.provider_id}'")
    data = _resolve_provider_data(provider.provider_id, data_map, cache, [])
    if not _is_enabled(data):
        raise ValueError(f"Provider config source not found for '{provider.provider_id}'")
    return provider, data


def list_providers(provider_dirs: Iterable[Path | str] | None = None) -> List[ProviderConfig]:
    """List all available provider configurations.

    Args:
        provider_dirs (Iterable[Path | str] | None): Additional provider directories.

    Returns:
        List[ProviderConfig]: Sorted provider configurations.
    """
    providers: Dict[str, ProviderConfig] = {}
    if provider_dirs is None:
        data_map = _load_provider_data_map()
    else:
        data_map = _load_provider_data_map(provider_dirs=provider_dirs)
    cache: Dict[str, dict] = {}
    for provider_id in data_map:
        try:
            data = _resolve_provider_data(provider_id, data_map, cache, [])
            if not _is_enabled(data):
                continue
            providers[provider_id] = _load_provider_from_data(provider_id, data)
        except ValueError as exc:
            LOGGER.warning("Skipping provider config %s: %s", provider_id, exc)
            continue
    return sorted(providers.values(), key=lambda item: item.provider_id)


def load_provider_config(
    selection: str, provider_dirs: Iterable[Path | str] | None = None
) -> ProviderConfig:
    """Load a single provider configuration by ID or name.

    Args:
        selection (str): Provider ID or name.
        provider_dirs (Iterable[Path | str] | None): Additional provider directories.

    Returns:
        ProviderConfig: Matching provider configuration.

    Raises:
        ValueError: If selection is empty or no provider matches.
    """
    if not selection:
        raise ValueError("Provider selection is required")

    normalized = _normalize_key(selection)
    if provider_dirs is None:
        candidates = list_providers()
    else:
        candidates = list_providers(provider_dirs=provider_dirs)
    for provider in candidates:
        if _normalize_key(provider.provider_id) == normalized:
            return provider
        if _normalize_key(provider.name) == normalized:
            return provider

    available = ", ".join(p.provider_id for p in candidates) or "none"
    raise ValueError(f"Unknown provider '{selection}'. Available: {available}")
