"""TLSA record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import TLSAConfig, TLSAMatchRule, TLSARecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _MATCH_ANY, _parse_match_mode
from .schema import RECORD_SCHEMA


def _parse_tlsa_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[TLSARecord]]:
    """Parse TLSA record entries.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw TLSA records mapping.

    Returns:
        Dict[str, List[TLSARecord]]: Parsed TLSA records.

    Raises:
        ValueError: If any TLSA records are invalid.
    """
    tlsa_records: Dict[str, List[TLSARecord]] = {}
    for name, entries in raw_records.items():
        entries_list = _require_list(provider_id, f"{field_label}.{name}", entries)
        parsed_entries: List[TLSARecord] = []
        for entry in entries_list:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries must be mappings"
                )
            usage = entry.get("usage")
            selector = entry.get("selector")
            matching_type = entry.get("matching_type")
            certificate_association = entry.get("certificate_association")
            if (
                usage is None
                or selector is None
                or matching_type is None
                or certificate_association is None
            ):
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries require usage, selector, matching_type, and certificate_association"
                )
            parsed_entries.append(
                TLSARecord(
                    usage=int(usage),
                    selector=int(selector),
                    matching_type=int(matching_type),
                    certificate_association=str(certificate_association),
                )
            )
        tlsa_records[str(name)] = parsed_entries
    return tlsa_records


def _parse_tlsa_match_rules(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, TLSAMatchRule]:
    """Parse TLSA negative match rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw TLSA rules mapping.

    Returns:
        Dict[str, TLSAMatchRule]: Parsed TLSA negative rules.

    Raises:
        ValueError: If any TLSA rules are invalid.
    """
    parsed: Dict[str, TLSAMatchRule] = {}
    for name, rule in raw_records.items():
        name_label = f"{field_label}.{name}"
        if isinstance(rule, dict):
            _reject_unknown_keys(provider_id, name_label, rule, {"match", "entries"})
            match_mode = _parse_match_mode(provider_id, name_label, rule.get("match"))
            if match_mode == _MATCH_ANY:
                parsed[str(name)] = TLSAMatchRule(match=match_mode, entries=[])
                continue
            entries_list = _require_list(
                provider_id, f"{name_label} entries", rule.get("entries", [])
            )
        else:
            match_mode = "exact"
            entries_list = _require_list(provider_id, name_label, rule)
        entries = _parse_tlsa_records(provider_id, field_label, {name: entries_list})[str(name)]
        if not entries:
            raise ValueError(
                f"Provider config {provider_id} {name_label} exact rules require at least one entry"
            )
        parsed[str(name)] = TLSAMatchRule(match=match_mode, entries=entries)
    return parsed


def _parse_tlsa(provider_id: str, records: dict) -> TLSAConfig | None:
    """Parse TLSA config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[TLSAConfig]: Parsed TLSA configuration if present.

    Raises:
        ValueError: If TLSA records are invalid.
    """
    if "tlsa" not in records:
        return None

    tlsa_section = _require_mapping(provider_id, "tlsa", records.get("tlsa"))
    _reject_unknown_keys(provider_id, "tlsa", tlsa_section, RECORD_SCHEMA["tlsa"]["section"])
    tlsa_required_raw = _require_mapping(
        provider_id, "tlsa required", tlsa_section.get("required", {})
    )
    tlsa_optional_raw = _require_mapping(
        provider_id, "tlsa optional", tlsa_section.get("optional", {})
    )
    tlsa_deprecated_raw = _require_mapping(
        provider_id, "tlsa deprecated", tlsa_section.get("deprecated", {})
    )
    tlsa_forbidden_raw = _require_mapping(
        provider_id, "tlsa forbidden", tlsa_section.get("forbidden", {})
    )
    tlsa_required = _parse_tlsa_records(provider_id, "tlsa required", tlsa_required_raw)
    tlsa_optional = _parse_tlsa_records(provider_id, "tlsa optional", tlsa_optional_raw)
    tlsa_deprecated = _parse_tlsa_match_rules(provider_id, "tlsa deprecated", tlsa_deprecated_raw)
    tlsa_forbidden = _parse_tlsa_match_rules(provider_id, "tlsa forbidden", tlsa_forbidden_raw)
    return TLSAConfig(
        required=tlsa_required,
        optional=tlsa_optional,
        deprecated=tlsa_deprecated,
        forbidden=tlsa_forbidden,
    )
