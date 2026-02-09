"""CAA record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import CAAMatchRule, CAAConfig, CAARecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _MATCH_ANY, _parse_match_mode
from .schema import RECORD_SCHEMA


def _parse_caa_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[CAARecord]]:
    """Parse a CAA records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw CAA records mapping.

    Returns:
        Dict[str, List[CAARecord]]: Parsed CAA records.

    Raises:
        ValueError: If any record entries are invalid.
    """
    caa_records: Dict[str, List[CAARecord]] = {}
    for name, entries in raw_records.items():
        entries_list = _require_list(provider_id, f"{field_label}.{name}", entries)
        parsed_entries: List[CAARecord] = []
        for entry in entries_list:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries must be mappings"
                )
            flags = entry.get("flags", entry.get("flag"))
            tag = entry.get("tag")
            value = entry.get("value")
            if flags is None or tag is None or value is None:
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries require flags, tag, and value"
                )
            parsed_entries.append(CAARecord(flags=int(flags), tag=str(tag), value=str(value)))
        caa_records[str(name)] = parsed_entries
    return caa_records


def _parse_caa_match_rules(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, CAAMatchRule]:
    """Parse CAA negative match rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw CAA records mapping.

    Returns:
        Dict[str, CAAMatchRule]: Parsed CAA negative rules.

    Raises:
        ValueError: If any CAA rules are invalid.
    """
    parsed: Dict[str, CAAMatchRule] = {}
    for name, rule in raw_records.items():
        name_label = f"{field_label}.{name}"
        if isinstance(rule, dict):
            _reject_unknown_keys(provider_id, name_label, rule, {"match", "entries"})
            match_mode = _parse_match_mode(provider_id, name_label, rule.get("match"))
            if match_mode == _MATCH_ANY:
                parsed[str(name)] = CAAMatchRule(match=match_mode, entries=[])
                continue
            entries_list = _require_list(
                provider_id, f"{name_label} entries", rule.get("entries", [])
            )
        else:
            match_mode = "exact"
            entries_list = _require_list(provider_id, name_label, rule)
        entries = _parse_caa_records(provider_id, field_label, {name: entries_list})[str(name)]
        if not entries:
            raise ValueError(
                f"Provider config {provider_id} {name_label} exact rules require at least one entry"
            )
        parsed[str(name)] = CAAMatchRule(match=match_mode, entries=entries)
    return parsed


def _parse_caa(provider_id: str, records: dict) -> CAAConfig | None:
    """Parse CAA config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[CAAConfig]: Parsed CAA configuration if present.

    Raises:
        ValueError: If CAA records are invalid.
    """
    if "caa" not in records:
        return None

    caa_section = _require_mapping(provider_id, "caa", records.get("caa"))
    _reject_unknown_keys(provider_id, "caa", caa_section, RECORD_SCHEMA["caa"]["section"])
    caa_required_raw = _require_mapping(
        provider_id, "caa required", caa_section.get("required", {})
    )
    caa_optional_raw = _require_mapping(
        provider_id, "caa optional", caa_section.get("optional", {})
    )
    caa_deprecated_raw = _require_mapping(
        provider_id, "caa deprecated", caa_section.get("deprecated", {})
    )
    caa_forbidden_raw = _require_mapping(
        provider_id, "caa forbidden", caa_section.get("forbidden", {})
    )
    caa_required = _parse_caa_records(provider_id, "caa required", caa_required_raw)
    caa_optional = _parse_caa_records(provider_id, "caa optional", caa_optional_raw)
    caa_deprecated = _parse_caa_match_rules(provider_id, "caa deprecated", caa_deprecated_raw)
    caa_forbidden = _parse_caa_match_rules(provider_id, "caa forbidden", caa_forbidden_raw)
    return CAAConfig(
        required=caa_required,
        optional=caa_optional,
        deprecated=caa_deprecated,
        forbidden=caa_forbidden,
    )
