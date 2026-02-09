"""Address record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import AddressConfig
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _parse_values_match_rules
from .schema import RECORD_SCHEMA


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
    _reject_unknown_keys(provider_id, "a", a_section, RECORD_SCHEMA["a"]["section"])
    a_required_raw = _require_mapping(provider_id, "a required", a_section.get("required", {}))
    a_optional_raw = _require_mapping(provider_id, "a optional", a_section.get("optional", {}))
    a_deprecated_raw = _require_mapping(
        provider_id, "a deprecated", a_section.get("deprecated", {})
    )
    a_forbidden_raw = _require_mapping(provider_id, "a forbidden", a_section.get("forbidden", {}))
    a_required = _parse_address_records(provider_id, "a required", a_required_raw)
    a_optional = _parse_address_records(provider_id, "a optional", a_optional_raw)
    a_deprecated = _parse_values_match_rules(provider_id, "a deprecated", a_deprecated_raw)
    a_forbidden = _parse_values_match_rules(provider_id, "a forbidden", a_forbidden_raw)
    return AddressConfig(
        required=a_required,
        optional=a_optional,
        deprecated=a_deprecated,
        forbidden=a_forbidden,
    )


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
    _reject_unknown_keys(provider_id, "aaaa", aaaa_section, RECORD_SCHEMA["aaaa"]["section"])
    aaaa_required_raw = _require_mapping(
        provider_id, "aaaa required", aaaa_section.get("required", {})
    )
    aaaa_optional_raw = _require_mapping(
        provider_id, "aaaa optional", aaaa_section.get("optional", {})
    )
    aaaa_deprecated_raw = _require_mapping(
        provider_id, "aaaa deprecated", aaaa_section.get("deprecated", {})
    )
    aaaa_forbidden_raw = _require_mapping(
        provider_id, "aaaa forbidden", aaaa_section.get("forbidden", {})
    )
    aaaa_required = _parse_address_records(provider_id, "aaaa required", aaaa_required_raw)
    aaaa_optional = _parse_address_records(provider_id, "aaaa optional", aaaa_optional_raw)
    aaaa_deprecated = _parse_values_match_rules(provider_id, "aaaa deprecated", aaaa_deprecated_raw)
    aaaa_forbidden = _parse_values_match_rules(provider_id, "aaaa forbidden", aaaa_forbidden_raw)
    return AddressConfig(
        required=aaaa_required,
        optional=aaaa_optional,
        deprecated=aaaa_deprecated,
        forbidden=aaaa_forbidden,
    )
