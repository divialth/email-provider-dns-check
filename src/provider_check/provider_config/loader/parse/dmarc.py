"""DMARC record parsing."""

from __future__ import annotations

from ...models import DMARCConfig
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
    _reject_unknown_keys(
        provider_id,
        "dmarc",
        dmarc_section,
        {
            "default_policy",
            "required_rua",
            "required_ruf",
            "required_tags",
            "rua_required",
            "ruf_required",
        },
    )
    default_policy = dmarc_section.get("default_policy", "reject")
    required_rua = _require_list(
        provider_id, "dmarc required_rua", dmarc_section.get("required_rua", [])
    )
    required_ruf = _require_list(
        provider_id, "dmarc required_ruf", dmarc_section.get("required_ruf", [])
    )
    rua_required = dmarc_section.get("rua_required", False)
    if not isinstance(rua_required, bool):
        raise ValueError(f"Provider config {provider_id} dmarc rua_required must be a boolean")
    ruf_required = dmarc_section.get("ruf_required", False)
    if not isinstance(ruf_required, bool):
        raise ValueError(f"Provider config {provider_id} dmarc ruf_required must be a boolean")
    required_tags_raw = _require_mapping(
        provider_id, "dmarc required_tags", dmarc_section.get("required_tags", {})
    )
    required_tags = {str(key).lower(): str(value) for key, value in required_tags_raw.items()}
    return DMARCConfig(
        default_policy=str(default_policy),
        required_rua=[str(value) for value in required_rua],
        required_ruf=[str(value) for value in required_ruf],
        required_tags=required_tags,
        rua_required=rua_required,
        ruf_required=ruf_required,
    )
