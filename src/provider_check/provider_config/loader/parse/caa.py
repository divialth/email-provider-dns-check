"""CAA record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import CAAConfig, CAARecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .schema import RECORD_SCHEMA


def _parse_caa_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[CAARecord]]:
    """Parse a CAA records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw CAA records mapping.

    Returns:
        Dict[str, List[CAARecord]]: Parsed CAA records.

    Raises:
        ValueError: If any record entries are invalid.
    """
    caa_records: Dict[str, List[CAARecord]] = {}
    for name, entries in raw_records.items():
        entries_list = _require_list(provider_id, f"{field_label}.{name}", entries)
        parsed_entries: List[CAARecord] = []
        for entry in entries_list:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries must be mappings"
                )
            flags = entry.get("flags", entry.get("flag"))
            tag = entry.get("tag")
            value = entry.get("value")
            if flags is None or tag is None or value is None:
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries require flags, tag, and value"
                )
            parsed_entries.append(CAARecord(flags=int(flags), tag=str(tag), value=str(value)))
        caa_records[str(name)] = parsed_entries
    return caa_records


def _parse_caa(provider_id: str, records: dict) -> CAAConfig | None:
    """Parse CAA config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[CAAConfig]: Parsed CAA configuration if present.

    Raises:
        ValueError: If CAA records are invalid.
    """
    if "caa" not in records:
        return None

    caa_section = _require_mapping(provider_id, "caa", records.get("caa"))
    _reject_unknown_keys(provider_id, "caa", caa_section, RECORD_SCHEMA["caa"]["section"])
    caa_required_raw = _require_mapping(
        provider_id, "caa required", caa_section.get("required", {})
    )
    caa_optional_raw = _require_mapping(
        provider_id, "caa optional", caa_section.get("optional", {})
    )
    caa_required = _parse_caa_records(provider_id, "caa required", caa_required_raw)
    caa_optional = _parse_caa_records(provider_id, "caa optional", caa_optional_raw)
    return CAAConfig(required=caa_required, optional=caa_optional)
