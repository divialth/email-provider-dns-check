"""MX record parsing."""

from __future__ import annotations

from typing import List

from ...models import MXConfig, MXRecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping


def _parse_mx_records(provider_id: str, field_label: str, raw_records: list) -> List[MXRecord]:
    """Parse MX record entries.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (list): Raw MX records list.

    Returns:
        List[MXRecord]: Parsed MX record entries.

    Raises:
        ValueError: If any MX records are invalid.
    """
    entries = _require_list(provider_id, field_label, raw_records)
    parsed: List[MXRecord] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(
                f"Provider config {provider_id} {field_label} entries must be mappings"
            )
        host = entry.get("host")
        if host is None:
            raise ValueError(f"Provider config {provider_id} {field_label} entries require host")
        priority = entry.get("priority")
        parsed.append(
            MXRecord(
                host=str(host),
                priority=int(priority) if priority is not None else None,
            )
        )
    return parsed


def _parse_mx(provider_id: str, records: dict) -> MXConfig | None:
    """Parse MX config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[MXConfig]: Parsed MX configuration if present.

    Raises:
        ValueError: If MX records are invalid.
    """
    if "mx" not in records:
        return None

    mx_section = _require_mapping(provider_id, "mx", records.get("mx"))
    _reject_unknown_keys(provider_id, "mx", mx_section, {"required", "optional"})
    required_raw = _require_list(provider_id, "mx required", mx_section.get("required", []))
    optional_raw = _require_list(provider_id, "mx optional", mx_section.get("optional", []))
    required = _parse_mx_records(provider_id, "mx required", required_raw)
    optional = _parse_mx_records(provider_id, "mx optional", optional_raw)
    return MXConfig(required=required, optional=optional)
