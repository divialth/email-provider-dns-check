"""TXT record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import TXTConfig, TXTSettings
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _parse_values_match_rules
from .schema import RECORD_SCHEMA


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
    _reject_unknown_keys(provider_id, "txt", txt_section, RECORD_SCHEMA["txt"]["section"])
    required_raw = _require_mapping(provider_id, "txt required", txt_section.get("required", {}))
    optional_raw = _require_mapping(provider_id, "txt optional", txt_section.get("optional", {}))
    deprecated_raw = _require_mapping(
        provider_id, "txt deprecated", txt_section.get("deprecated", {})
    )
    forbidden_raw = _require_mapping(provider_id, "txt forbidden", txt_section.get("forbidden", {}))
    settings_raw = _require_mapping(provider_id, "txt settings", txt_section.get("settings", {}))
    _reject_unknown_keys(
        provider_id,
        "txt settings",
        settings_raw,
        RECORD_SCHEMA["txt"]["settings"],
    )

    required: Dict[str, List[str]] = {}
    for name, values in required_raw.items():
        values_list = _require_list(provider_id, f"txt required.{name}", values)
        required_values = [str(value) for value in values_list]
        required[str(name)] = required_values

    optional: Dict[str, List[str]] = {}
    for name, values in optional_raw.items():
        values_list = _require_list(provider_id, f"txt optional.{name}", values)
        optional_values = [str(value) for value in values_list]
        optional[str(name)] = optional_values

    deprecated = _parse_values_match_rules(provider_id, "txt deprecated", deprecated_raw)
    forbidden = _parse_values_match_rules(provider_id, "txt forbidden", forbidden_raw)

    verification_required = settings_raw.get("verification_required", False)
    if not isinstance(verification_required, bool):
        raise ValueError(
            f"Provider config {provider_id} txt settings.verification_required must be a boolean"
        )
    return TXTConfig(
        required=required,
        optional=optional,
        deprecated=deprecated,
        forbidden=forbidden,
        settings=TXTSettings(verification_required=verification_required),
    )
