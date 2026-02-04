"""Shared helpers and constants for provider configuration."""

from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

CONFIG_DIR_NAME = "provider-dns-check"
PROVIDER_DIR_NAME = "providers"
TEMPLATE_DIR_NAME = "templates"
PROVIDER_PACKAGE = "provider_check.resources.providers"

LOGGER = logging.getLogger(__name__)

_RESERVED_VARIABLES = {"selector", "domain"}

SYSTEM_CONFIG_DIRS = [
    Path("/etc") / CONFIG_DIR_NAME,
    Path("/usr/local/etc") / CONFIG_DIR_NAME,
]


def _normalize_key(value: str) -> str:
    """Normalize provider identifiers for matching.

    Args:
        value (str): Input string to normalize.

    Returns:
        str: Normalized identifier.
    """
    return value.strip().lower().replace(" ", "_").replace(".", "_")


def _require_mapping(provider_id: str, field: str, value: object | None) -> dict:
    """Ensure a configuration field is a mapping.

    Args:
        provider_id (str): Provider identifier for error messages.
        field (str): Field name being validated.
        value (object | None): Value to validate.

    Returns:
        dict: Validated mapping.

    Raises:
        ValueError: If the value is missing or not a mapping.
    """
    if value is None:
        raise ValueError(f"Provider config {provider_id} {field} must be a mapping")
    if not isinstance(value, dict):
        raise ValueError(f"Provider config {provider_id} {field} must be a mapping")
    return value


def _require_list(provider_id: str, field: str, value: object | None) -> list:
    """Ensure a configuration field is a list.

    Args:
        provider_id (str): Provider identifier for error messages.
        field (str): Field name being validated.
        value (object | None): Value to validate.

    Returns:
        list: Validated list.

    Raises:
        ValueError: If the value is missing or not a list.
    """
    if value is None:
        raise ValueError(f"Provider config {provider_id} {field} must be a list")
    if not isinstance(value, list):
        raise ValueError(f"Provider config {provider_id} {field} must be a list")
    return value


def _require_variables(provider_id: str, value: object | None) -> dict:
    """Ensure provider variables are a mapping.

    Args:
        provider_id (str): Provider identifier for error messages.
        value (object | None): Variables section value.

    Returns:
        dict: Variables mapping or empty dict.

    Raises:
        ValueError: If the variables value is not a mapping.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Provider config {provider_id} variables must be a mapping")
    return value


def external_config_dirs() -> List[Path]:
    """Return directories that may contain external provider configs.

    Returns:
        List[Path]: Ordered list of user and system config directories.
    """
    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_home:
        user_dir = Path(xdg_home) / CONFIG_DIR_NAME
    else:
        user_dir = Path.home() / ".config" / CONFIG_DIR_NAME
    return [user_dir, *SYSTEM_CONFIG_DIRS]


def _normalize_extends(provider_id: str, value: object | None) -> List[str]:
    """Normalize the extends field into a list of provider IDs.

    Args:
        provider_id (str): Provider identifier for error messages.
        value (object | None): Extends value to normalize.

    Returns:
        List[str]: Normalized list of provider IDs.

    Raises:
        ValueError: If the extends value has invalid types or entries.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise ValueError(f"Provider config {provider_id} extends must be a string or list")
    normalized: List[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"Provider config {provider_id} extends entries must be strings")
        trimmed = item.strip()
        if not trimmed:
            raise ValueError(f"Provider config {provider_id} extends entries must be non-empty")
        normalized.append(trimmed)
    return normalized


def _merge_provider_data(base: dict, override: dict) -> dict:
    """Merge two provider config mappings.

    Args:
        base (dict): Base mapping.
        override (dict): Override mapping.

    Returns:
        dict: Deep-merged mapping with overrides applied.
    """
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if value is None:
            merged.pop(key, None)
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_provider_data(merged[key], value)
            continue
        merged[key] = copy.deepcopy(value)
    return merged


class _SafeFormatDict(dict):
    """Dictionary that preserves unknown format keys."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - defensive
        """Return a placeholder for missing format keys.

        Args:
            key (str): Missing format key.

        Returns:
            str: Placeholder string with the missing key.
        """
        return "{" + key + "}"


def _format_string(value: Optional[str], variables: Dict[str, str]) -> Optional[str]:
    """Format a string using provider variables.

    Args:
        value (Optional[str]): Template string to format.
        variables (Dict[str, str]): Variables for template formatting.

    Returns:
        Optional[str]: Formatted string or None if value is None.
    """
    if value is None:
        return None
    return value.format_map(_SafeFormatDict(variables))
