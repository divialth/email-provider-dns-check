"""DKIM record parsing."""

from __future__ import annotations

from ...models import DKIMConfig, DKIMRequired
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .schema import RECORD_SCHEMA


def _parse_dkim(provider_id: str, records: dict) -> DKIMConfig | None:
    """Parse DKIM config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[DKIMConfig]: Parsed DKIM configuration if present.

    Raises:
        ValueError: If DKIM records are invalid.
    """
    if "dkim" not in records:
        return None

    dkim_section = _require_mapping(provider_id, "dkim", records.get("dkim"))
    _reject_unknown_keys(provider_id, "dkim", dkim_section, RECORD_SCHEMA["dkim"]["section"])
    required_section = _require_mapping(
        provider_id, "dkim required", dkim_section.get("required", {})
    )
    _reject_unknown_keys(
        provider_id,
        "dkim required",
        required_section,
        RECORD_SCHEMA["dkim"]["required"],
    )

    selectors = _require_list(provider_id, "dkim selectors", required_section.get("selectors", []))
    record_type = str(required_section.get("record_type", "cname")).lower()
    if record_type not in {"cname", "txt"}:
        raise ValueError(f"Provider config {provider_id} dkim record_type must be cname or txt")
    target_template = required_section.get("target_template")
    if record_type == "cname" and not target_template:
        raise ValueError(f"Provider config {provider_id} dkim requires target_template for cname")
    txt_values_raw = _require_mapping(
        provider_id, "dkim txt_values", required_section.get("txt_values", {})
    )
    txt_values = {str(key): str(value) for key, value in txt_values_raw.items()}
    return DKIMConfig(
        required=DKIMRequired(
            selectors=[str(selector) for selector in selectors],
            record_type=record_type,
            target_template=str(target_template) if target_template else None,
            txt_values=txt_values,
        )
    )
