"""SPF record parsing."""

from __future__ import annotations

from ...models import SPFConfig
from ...utils import _require_list, _require_mapping


def _parse_spf(provider_id: str, records: dict) -> SPFConfig | None:
    """Parse SPF config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[SPFConfig]: Parsed SPF configuration if present.

    Raises:
        ValueError: If SPF records are invalid.
    """
    if "spf" not in records:
        return None

    spf_section = _require_mapping(provider_id, "spf", records.get("spf"))
    required = _require_list(
        provider_id, "spf required_includes", spf_section.get("required_includes", [])
    )
    required_mechanisms = _require_list(
        provider_id,
        "spf required_mechanisms",
        spf_section.get("required_mechanisms", []),
    )
    allowed_mechanisms = _require_list(
        provider_id,
        "spf allowed_mechanisms",
        spf_section.get("allowed_mechanisms", []),
    )
    required_modifiers_raw = _require_mapping(
        provider_id,
        "spf required_modifiers",
        spf_section.get("required_modifiers", {}),
    )
    required_modifiers = {
        str(key).lower(): str(value) for key, value in required_modifiers_raw.items()
    }
    return SPFConfig(
        required_includes=[str(value) for value in required],
        strict_record=spf_section.get("strict_record"),
        required_mechanisms=[str(value) for value in required_mechanisms],
        allowed_mechanisms=[str(value) for value in allowed_mechanisms],
        required_modifiers=required_modifiers,
    )
