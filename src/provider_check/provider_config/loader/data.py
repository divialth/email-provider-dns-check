"""Provider config data loading helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml

from ..utils import LOGGER, _merge_provider_data, _normalize_extends


def _load_yaml(path: object) -> dict:
    """Load a provider config YAML file.

    Args:
        path (object): Path-like object with read_text() and name.

    Returns:
        dict: Parsed YAML mapping.

    Raises:
        ValueError: If the YAML file does not contain a mapping.
    """
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Provider config {path} is not a mapping")
    return data


def _is_enabled(data: dict) -> bool:
    """Check if a provider config is enabled.

    Args:
        data (dict): Provider config mapping.

    Returns:
        bool: True if enabled.

    Raises:
        ValueError: If enabled is present but not a boolean.
    """
    enabled = data.get("enabled", True)
    if isinstance(enabled, bool):
        return enabled
    raise ValueError("Provider config enabled must be a boolean")


def _load_provider_data_map() -> Dict[str, dict]:
    """Load provider configuration data from available sources.

    Returns:
        Dict[str, dict]: Mapping of provider ID to raw config data.
    """
    from . import _iter_provider_paths

    providers: Dict[str, dict] = {}
    for path in _iter_provider_paths():
        provider_id = Path(path.name).stem
        if provider_id in providers:
            continue
        try:
            data = _load_yaml(path)
        except ValueError as exc:
            LOGGER.warning("Skipping provider config %s: %s", path, exc)
            continue
        providers[provider_id] = data
    return providers


def _resolve_provider_data(
    provider_id: str,
    data_map: Dict[str, dict],
    cache: Dict[str, dict],
    stack: List[str],
) -> dict:
    """Resolve provider config data with inheritance.

    Args:
        provider_id (str): Provider ID to resolve.
        data_map (Dict[str, dict]): Raw provider data by ID.
        cache (Dict[str, dict]): Cache of resolved provider data.
        stack (List[str]): Stack of provider IDs for cycle detection.

    Returns:
        dict: Fully resolved provider data.

    Raises:
        ValueError: If an extends cycle or unknown provider is detected.
    """
    if provider_id in cache:
        return cache[provider_id]
    if provider_id in stack:
        cycle = " -> ".join([*stack, provider_id])
        raise ValueError(f"Provider config extends cycle detected: {cycle}")
    if provider_id not in data_map:
        raise ValueError(f"Provider config extends unknown provider '{provider_id}'")

    raw = data_map[provider_id]
    extends = _normalize_extends(provider_id, raw.get("extends"))
    merged: dict = {}
    stack.append(provider_id)
    for base_id in extends:
        base_data = _resolve_provider_data(base_id, data_map, cache, stack)
        base_payload = {key: value for key, value in base_data.items() if key != "enabled"}
        merged = _merge_provider_data(merged, base_payload)
    stack.pop()

    stripped = {key: value for key, value in raw.items() if key not in {"extends"}}
    merged = _merge_provider_data(merged, stripped)
    cache[provider_id] = merged
    return merged
