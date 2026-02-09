"""Helpers for parsing exact/any negative match rules."""

from __future__ import annotations

from typing import Dict, List

from ...models import CNAMEMatchRule, ValuesMatchRule
from ...utils import _reject_unknown_keys, _require_list

_MATCH_EXACT = "exact"
_MATCH_ANY = "any"
_MATCH_MODES = frozenset({_MATCH_EXACT, _MATCH_ANY})


def _parse_match_mode(provider_id: str, field_label: str, mode: object | None) -> str:
    """Parse a match mode string.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        mode (object | None): Raw mode value.

    Returns:
        str: Normalized match mode.

    Raises:
        ValueError: If the mode is invalid.
    """
    normalized = str(mode or _MATCH_EXACT).lower()
    if normalized not in _MATCH_MODES:
        allowed = ", ".join(sorted(_MATCH_MODES))
        raise ValueError(
            f"Provider config {provider_id} {field_label} match must be one of: {allowed}"
        )
    return normalized


def _parse_values_match_rules(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, ValuesMatchRule]:
    """Parse mapping-based list value match rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw rules mapping.

    Returns:
        Dict[str, ValuesMatchRule]: Parsed rules keyed by record name.

    Raises:
        ValueError: If any rules are invalid.
    """
    parsed: Dict[str, ValuesMatchRule] = {}
    for name, value in raw_records.items():
        name_label = f"{field_label}.{name}"
        if isinstance(value, dict):
            _reject_unknown_keys(provider_id, name_label, value, {"match", "values"})
            match_mode = _parse_match_mode(provider_id, name_label, value.get("match"))
            if match_mode == _MATCH_ANY:
                parsed[str(name)] = ValuesMatchRule(match=match_mode, values=[])
                continue
            values_list = _require_list(
                provider_id, f"{name_label} values", value.get("values", [])
            )
        else:
            match_mode = _MATCH_EXACT
            values_list = _require_list(provider_id, name_label, value)
        parsed_values = [str(entry) for entry in values_list]
        if not parsed_values:
            raise ValueError(
                f"Provider config {provider_id} {name_label} exact rules require at least one value"
            )
        parsed[str(name)] = ValuesMatchRule(match=match_mode, values=parsed_values)
    return parsed


def _parse_cname_match_rules(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, CNAMEMatchRule]:
    """Parse CNAME negative match rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw rules mapping.

    Returns:
        Dict[str, CNAMEMatchRule]: Parsed rules keyed by record name.

    Raises:
        ValueError: If any rules are invalid.
    """
    parsed: Dict[str, CNAMEMatchRule] = {}
    for name, value in raw_records.items():
        name_label = f"{field_label}.{name}"
        if isinstance(value, dict):
            _reject_unknown_keys(provider_id, name_label, value, {"match", "target"})
            match_mode = _parse_match_mode(provider_id, name_label, value.get("match"))
            if match_mode == _MATCH_ANY:
                parsed[str(name)] = CNAMEMatchRule(match=match_mode, target=None)
                continue
            target = value.get("target")
        else:
            match_mode = _MATCH_EXACT
            target = value
        if target is None or isinstance(target, (dict, list)):
            raise ValueError(
                f"Provider config {provider_id} {name_label} exact rules require a string target"
            )
        parsed[str(name)] = CNAMEMatchRule(match=match_mode, target=str(target))
    return parsed


__all__ = [
    "_MATCH_ANY",
    "_MATCH_EXACT",
    "_parse_cname_match_rules",
    "_parse_match_mode",
    "_parse_values_match_rules",
]
