"""Provider config metadata parsing."""

from __future__ import annotations

from typing import Optional, Tuple


def _parse_provider_metadata(
    provider_id: str, data: dict
) -> tuple[str, str, Optional[str], Optional[str]]:
    """Parse provider metadata fields.

    Args:
        provider_id (str): Provider identifier used in error messages.
        data (dict): Provider configuration mapping.

    Returns:
        tuple[str, str, Optional[str], Optional[str]]: Version, name, short description,
            and long description values.

    Raises:
        ValueError: If required metadata is missing or has invalid types.
    """
    version = data.get("version")
    if version is None:
        raise ValueError(f"Provider config {provider_id} is missing version")
    provider_name = data.get("name", provider_id)
    short_description = data.get("short_description")
    if short_description is not None and not isinstance(short_description, str):
        raise ValueError(f"Provider config {provider_id} short_description must be a string")
    long_description = data.get("long_description")
    if long_description is not None and not isinstance(long_description, str):
        raise ValueError(f"Provider config {provider_id} long_description must be a string")
    return str(version), str(provider_name), short_description, long_description
