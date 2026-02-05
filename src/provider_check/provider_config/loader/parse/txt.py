"""TXT record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import TXTConfig
from ...utils import _reject_unknown_keys, _require_list, _require_mapping


def _parse_txt(provider_id: str, records: dict) -> TXTConfig | None:
    """Parse TXT config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[TXTConfig]: Parsed TXT configuration if present.

    Raises:
        ValueError: If TXT records are invalid.
    """
    if "txt" not in records:
        return None

    txt_section = _require_mapping(provider_id, "txt", records.get("txt"))
    _reject_unknown_keys(
        provider_id,
        "txt",
        txt_section,
        {"records", "records_optional", "verification_required"},
    )
    records_raw = _require_mapping(provider_id, "txt records", txt_section.get("records", {}))
    records_required: Dict[str, List[str]] = {}
    for name, values in records_raw.items():
        values_list = _require_list(provider_id, f"txt records.{name}", values)
        required_values = [str(value) for value in values_list]
        records_required[str(name)] = required_values
    records_optional_raw = _require_mapping(
        provider_id, "txt records_optional", txt_section.get("records_optional", {})
    )
    records_optional: Dict[str, List[str]] = {}
    for name, values in records_optional_raw.items():
        values_list = _require_list(provider_id, f"txt records_optional.{name}", values)
        optional_values = [str(value) for value in values_list]
        records_optional[str(name)] = optional_values
    verification_required = txt_section.get("verification_required", False)
    if not isinstance(verification_required, bool):
        raise ValueError(
            f"Provider config {provider_id} txt verification_required must be a boolean"
        )
    return TXTConfig(
        records=records_required,
        records_optional=records_optional,
        verification_required=verification_required,
    )
