"""Address record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import AddressConfig
from ...utils import _require_list, _require_mapping


def _parse_address_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[str]]:
    """Parse A/AAAA record mappings.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw mapping of name to values.

    Returns:
        Dict[str, List[str]]: Parsed record mapping.

    Raises:
        ValueError: If any record values are invalid.
    """
    parsed: Dict[str, List[str]] = {}
    for name, values in raw_records.items():
        values_list = _require_list(provider_id, f"{field_label}.{name}", values)
        parsed[str(name)] = [str(value) for value in values_list]
    return parsed


def _parse_a(provider_id: str, records: dict) -> AddressConfig | None:
    """Parse A record config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[AddressConfig]: Parsed A record configuration if present.
    """
    if "a" not in records:
        return None

    a_section = _require_mapping(provider_id, "a", records.get("a"))
    a_records_raw = _require_mapping(provider_id, "a records", a_section.get("records", {}))
    a_optional_raw = _require_mapping(
        provider_id, "a records_optional", a_section.get("records_optional", {})
    )
    a_records = _parse_address_records(provider_id, "a records", a_records_raw)
    a_optional_records = _parse_address_records(provider_id, "a records_optional", a_optional_raw)
    return AddressConfig(records=a_records, records_optional=a_optional_records)


def _parse_aaaa(provider_id: str, records: dict) -> AddressConfig | None:
    """Parse AAAA record config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[AddressConfig]: Parsed AAAA record configuration if present.
    """
    if "aaaa" not in records:
        return None

    aaaa_section = _require_mapping(provider_id, "aaaa", records.get("aaaa"))
    aaaa_records_raw = _require_mapping(
        provider_id, "aaaa records", aaaa_section.get("records", {})
    )
    aaaa_optional_raw = _require_mapping(
        provider_id, "aaaa records_optional", aaaa_section.get("records_optional", {})
    )
    aaaa_records = _parse_address_records(provider_id, "aaaa records", aaaa_records_raw)
    aaaa_optional_records = _parse_address_records(
        provider_id, "aaaa records_optional", aaaa_optional_raw
    )
    return AddressConfig(records=aaaa_records, records_optional=aaaa_optional_records)
