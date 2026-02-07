"""SPF record parsing."""

from __future__ import annotations

from ...models import SPFConfig, SPFOptional, SPFRequired
from ...utils import _reject_unknown_keys, _require_list, _require_mapping

_SPF_POLICIES = {"hardfail", "softfail", "neutral", "allow"}


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
    _reject_unknown_keys(provider_id, "spf", spf_section, {"required", "optional"})
    required_section = _require_mapping(
        provider_id, "spf required", spf_section.get("required", {})
    )
    optional_section = _require_mapping(
        provider_id, "spf optional", spf_section.get("optional", {})
    )
    _reject_unknown_keys(
        provider_id,
        "spf required",
        required_section,
        {"policy", "includes", "mechanisms", "modifiers"},
    )
    _reject_unknown_keys(provider_id, "spf optional", optional_section, {"mechanisms", "modifiers"})

    policy = required_section.get("policy")
    if not isinstance(policy, str):
        raise ValueError(f"Provider config {provider_id} spf required policy must be a string")
    normalized_policy = policy.lower()
    if normalized_policy not in _SPF_POLICIES:
        allowed = ", ".join(sorted(_SPF_POLICIES))
        raise ValueError(
            f"Provider config {provider_id} spf required policy must be one of: {allowed}"
        )

    includes = _require_list(
        provider_id, "spf required includes", required_section.get("includes", [])
    )
    required_mechanisms = _require_list(
        provider_id, "spf required mechanisms", required_section.get("mechanisms", [])
    )
    required_modifiers_raw = _require_mapping(
        provider_id, "spf required modifiers", required_section.get("modifiers", {})
    )
    required_modifiers = {
        str(key).lower(): str(value) for key, value in required_modifiers_raw.items()
    }

    optional_mechanisms = _require_list(
        provider_id, "spf optional mechanisms", optional_section.get("mechanisms", [])
    )
    optional_modifiers_raw = _require_mapping(
        provider_id, "spf optional modifiers", optional_section.get("modifiers", {})
    )
    optional_modifiers = {
        str(key).lower(): str(value) for key, value in optional_modifiers_raw.items()
    }

    return SPFConfig(
        required=SPFRequired(
            policy=normalized_policy,
            includes=[str(value) for value in includes],
            mechanisms=[str(value) for value in required_mechanisms],
            modifiers=required_modifiers,
        ),
        optional=SPFOptional(
            mechanisms=[str(value) for value in optional_mechanisms],
            modifiers=optional_modifiers,
        ),
    )
