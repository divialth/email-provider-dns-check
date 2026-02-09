"""MX record parsing."""

from __future__ import annotations

from typing import List

from ...models import MXConfig, MXNegativePolicy, MXNegativeRules, MXRecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _MATCH_ANY, _MATCH_EXACT, _parse_match_mode
from .schema import RECORD_SCHEMA


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


def _parse_mx_negative_rules(
    provider_id: str, field_label: str, raw_rules: object
) -> MXNegativeRules:
    """Parse MX deprecated/forbidden rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_rules (object): Raw negative-rules object.

    Returns:
        MXNegativeRules: Parsed MX negative rules.

    Raises:
        ValueError: If MX negative rules are invalid.
    """
    rules_section = _require_mapping(provider_id, field_label, raw_rules)
    _reject_unknown_keys(provider_id, field_label, rules_section, RECORD_SCHEMA["mx"]["negative"])
    policy_label = f"{field_label} policy"
    policy_section = _require_mapping(provider_id, policy_label, rules_section.get("policy", {}))
    _reject_unknown_keys(provider_id, policy_label, policy_section, RECORD_SCHEMA["mx"]["policy"])
    match_mode = _parse_match_mode(provider_id, policy_label, policy_section.get("match"))
    entries_label = f"{field_label} entries"
    entries_raw = _require_list(provider_id, entries_label, rules_section.get("entries", []))
    explicit_exact = "match" in policy_section and match_mode == _MATCH_EXACT
    if match_mode == _MATCH_ANY and "entries" in rules_section:
        raise ValueError(
            f"Provider config {provider_id} {field_label} entries are not allowed when policy.match is any"
        )
    if match_mode == _MATCH_EXACT and "entries" in rules_section and not entries_raw:
        raise ValueError(
            f"Provider config {provider_id} {field_label} exact policy requires at least one entry"
        )
    if explicit_exact and not entries_raw:
        raise ValueError(
            f"Provider config {provider_id} {field_label} exact policy requires at least one entry"
        )
    entries: List[MXRecord] = []
    if match_mode == _MATCH_EXACT:
        entries = _parse_mx_records(provider_id, entries_label, entries_raw)
    return MXNegativeRules(policy=MXNegativePolicy(match=match_mode), entries=entries)


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
    _reject_unknown_keys(provider_id, "mx", mx_section, RECORD_SCHEMA["mx"]["section"])
    required_raw = _require_list(provider_id, "mx required", mx_section.get("required", []))
    optional_raw = _require_list(provider_id, "mx optional", mx_section.get("optional", []))
    deprecated_raw = _require_mapping(
        provider_id, "mx deprecated", mx_section.get("deprecated", {})
    )
    forbidden_raw = _require_mapping(provider_id, "mx forbidden", mx_section.get("forbidden", {}))
    required = _parse_mx_records(provider_id, "mx required", required_raw)
    optional = _parse_mx_records(provider_id, "mx optional", optional_raw)
    deprecated = _parse_mx_negative_rules(provider_id, "mx deprecated", deprecated_raw)
    forbidden = _parse_mx_negative_rules(provider_id, "mx forbidden", forbidden_raw)
    return MXConfig(
        required=required,
        optional=optional,
        deprecated=deprecated,
        forbidden=forbidden,
    )
