"""CNAME record parsing."""

from __future__ import annotations

from typing import Dict

from ...models import CNAMEConfig
from ...utils import _require_mapping


def _parse_cname(provider_id: str, records: dict) -> CNAMEConfig | None:
    """Parse CNAME config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[CNAMEConfig]: Parsed CNAME configuration if present.

    Raises:
        ValueError: If CNAME records are invalid.
    """
    if "cname" not in records:
        return None

    cname_section = _require_mapping(provider_id, "cname", records.get("cname"))
    cname_records_raw = _require_mapping(
        provider_id, "cname records", cname_section.get("records", {})
    )
    cname_optional_raw = _require_mapping(
        provider_id, "cname records_optional", cname_section.get("records_optional", {})
    )
    cname_records: Dict[str, str] = {}
    for name, target in cname_records_raw.items():
        if target is None or isinstance(target, (dict, list)):
            raise ValueError(
                f"Provider config {provider_id} cname record '{name}' must be a string"
            )
        cname_records[str(name)] = str(target)
    cname_optional_records: Dict[str, str] = {}
    for name, target in cname_optional_raw.items():
        if target is None or isinstance(target, (dict, list)):
            raise ValueError(
                f"Provider config {provider_id} cname records_optional '{name}' must be a string"
            )
        cname_optional_records[str(name)] = str(target)
    return CNAMEConfig(records=cname_records, records_optional=cname_optional_records)
