"""PTR record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import PTRConfig
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .schema import RECORD_SCHEMA


def _is_reverse_dns_name(name: str) -> bool:
    """Return whether a name is a reverse DNS label.

    Args:
        name (str): Name to inspect.

    Returns:
        bool: True when the name ends with ``in-addr.arpa`` or ``ip6.arpa``.
    """
    normalized = name.strip().lower().rstrip(".")
    return normalized.endswith(".in-addr.arpa") or normalized.endswith(".ip6.arpa")


def _parse_ptr_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[str]]:
    """Parse PTR record mappings.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw mapping of reverse names to values.

    Returns:
        Dict[str, List[str]]: Parsed PTR mapping.

    Raises:
        ValueError: If PTR values are not lists.
    """
    parsed: Dict[str, List[str]] = {}
    for name, values in raw_records.items():
        if not _is_reverse_dns_name(str(name)):
            raise ValueError(
                f"Provider config {provider_id} {field_label} '{name}' must be a reverse DNS name "
                "ending with in-addr.arpa or ip6.arpa"
            )
        values_list = _require_list(provider_id, f"{field_label}.{name}", values)
        parsed[str(name)] = [str(value) for value in values_list]
    return parsed


def _parse_ptr(provider_id: str, records: dict) -> PTRConfig | None:
    """Parse PTR config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[PTRConfig]: Parsed PTR configuration if present.
    """
    if "ptr" not in records:
        return None

    ptr_section = _require_mapping(provider_id, "ptr", records.get("ptr"))
    _reject_unknown_keys(provider_id, "ptr", ptr_section, RECORD_SCHEMA["ptr"]["section"])
    ptr_required_raw = _require_mapping(
        provider_id, "ptr required", ptr_section.get("required", {})
    )
    ptr_optional_raw = _require_mapping(
        provider_id, "ptr optional", ptr_section.get("optional", {})
    )
    ptr_required = _parse_ptr_records(provider_id, "ptr required", ptr_required_raw)
    ptr_optional = _parse_ptr_records(provider_id, "ptr optional", ptr_optional_raw)
    return PTRConfig(required=ptr_required, optional=ptr_optional)
