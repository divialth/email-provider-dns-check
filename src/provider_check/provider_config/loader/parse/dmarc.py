"""DMARC record parsing."""

from __future__ import annotations

from ...models import DMARCConfig, DMARCOptional, DMARCRequired, DMARCSettings
from ...utils import _reject_unknown_keys, _require_list, _require_mapping


def _parse_dmarc(provider_id: str, records: dict) -> DMARCConfig | None:
    """Parse DMARC config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[DMARCConfig]: Parsed DMARC configuration if present.

    Raises:
        ValueError: If DMARC records are invalid.
    """
    if "dmarc" not in records:
        return None

    dmarc_section = _require_mapping(provider_id, "dmarc", records.get("dmarc"))
    _reject_unknown_keys(provider_id, "dmarc", dmarc_section, {"required", "optional", "settings"})
    required_section = _require_mapping(
        provider_id, "dmarc required", dmarc_section.get("required", {})
    )
    optional_section = _require_mapping(
        provider_id, "dmarc optional", dmarc_section.get("optional", {})
    )
    settings_section = _require_mapping(
        provider_id, "dmarc settings", dmarc_section.get("settings", {})
    )
    _reject_unknown_keys(
        provider_id,
        "dmarc required",
        required_section,
        {"policy", "rua", "ruf", "tags"},
    )
    _reject_unknown_keys(provider_id, "dmarc optional", optional_section, {"rua", "ruf"})
    _reject_unknown_keys(
        provider_id, "dmarc settings", settings_section, {"rua_required", "ruf_required"}
    )

    policy = required_section.get("policy", "reject")
    if policy is None or not isinstance(policy, str):
        raise ValueError(f"Provider config {provider_id} dmarc required policy must be a string")

    required_rua = _require_list(provider_id, "dmarc required rua", required_section.get("rua", []))
    required_ruf = _require_list(provider_id, "dmarc required ruf", required_section.get("ruf", []))
    required_tags_raw = _require_mapping(
        provider_id, "dmarc required tags", required_section.get("tags", {})
    )
    required_tags = {str(key).lower(): str(value) for key, value in required_tags_raw.items()}

    optional_rua = _require_list(provider_id, "dmarc optional rua", optional_section.get("rua", []))
    optional_ruf = _require_list(provider_id, "dmarc optional ruf", optional_section.get("ruf", []))

    rua_required = settings_section.get("rua_required", False)
    if not isinstance(rua_required, bool):
        raise ValueError(
            f"Provider config {provider_id} dmarc settings.rua_required must be a boolean"
        )
    ruf_required = settings_section.get("ruf_required", False)
    if not isinstance(ruf_required, bool):
        raise ValueError(
            f"Provider config {provider_id} dmarc settings.ruf_required must be a boolean"
        )

    return DMARCConfig(
        required=DMARCRequired(
            policy=str(policy),
            rua=[str(value) for value in required_rua],
            ruf=[str(value) for value in required_ruf],
            tags=required_tags,
        ),
        optional=DMARCOptional(
            rua=[str(value) for value in optional_rua],
            ruf=[str(value) for value in optional_ruf],
        ),
        settings=DMARCSettings(rua_required=rua_required, ruf_required=ruf_required),
    )
