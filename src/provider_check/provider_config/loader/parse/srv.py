"""SRV record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import SRVConfig, SRVMatchRule, SRVRecord
from ...utils import _reject_unknown_keys, _require_list, _require_mapping
from .match import _MATCH_ANY, _parse_match_mode
from .schema import RECORD_SCHEMA


def _parse_srv_records(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, List[SRVRecord]]:
    """Parse SRV record entries.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw SRV records mapping.

    Returns:
        Dict[str, List[SRVRecord]]: Parsed SRV records.

    Raises:
        ValueError: If any SRV records are invalid.
    """
    srv_records: Dict[str, List[SRVRecord]] = {}
    for name, entries in raw_records.items():
        entries_list = _require_list(provider_id, f"{field_label}.{name}", entries)
        parsed_entries: List[SRVRecord] = []
        for entry in entries_list:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries must be mappings"
                )
            priority = entry.get("priority")
            weight = entry.get("weight")
            port = entry.get("port")
            target = entry.get("target")
            if priority is None or weight is None or port is None or target is None:
                raise ValueError(
                    f"Provider config {provider_id} {field_label}.{name} entries require priority, weight, port, and target"
                )
            parsed_entries.append(
                SRVRecord(
                    priority=int(priority),
                    weight=int(weight),
                    port=int(port),
                    target=str(target),
                )
            )
        srv_records[str(name)] = parsed_entries
    return srv_records


def _parse_srv_match_rules(
    provider_id: str, field_label: str, raw_records: Dict[str, object]
) -> Dict[str, SRVMatchRule]:
    """Parse SRV negative match rules.

    Args:
        provider_id (str): Provider identifier used in error messages.
        field_label (str): Label used in error messages.
        raw_records (Dict[str, object]): Raw SRV rules mapping.

    Returns:
        Dict[str, SRVMatchRule]: Parsed SRV negative rules.

    Raises:
        ValueError: If any SRV rules are invalid.
    """
    parsed: Dict[str, SRVMatchRule] = {}
    for name, rule in raw_records.items():
        name_label = f"{field_label}.{name}"
        if isinstance(rule, dict):
            _reject_unknown_keys(provider_id, name_label, rule, {"match", "entries"})
            match_mode = _parse_match_mode(provider_id, name_label, rule.get("match"))
            if match_mode == _MATCH_ANY:
                parsed[str(name)] = SRVMatchRule(match=match_mode, entries=[])
                continue
            entries_list = _require_list(
                provider_id, f"{name_label} entries", rule.get("entries", [])
            )
        else:
            match_mode = "exact"
            entries_list = _require_list(provider_id, name_label, rule)
        entries = _parse_srv_records(provider_id, field_label, {name: entries_list})[str(name)]
        if not entries:
            raise ValueError(
                f"Provider config {provider_id} {name_label} exact rules require at least one entry"
            )
        parsed[str(name)] = SRVMatchRule(match=match_mode, entries=entries)
    return parsed


def _parse_srv(provider_id: str, records: dict) -> SRVConfig | None:
    """Parse SRV config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[SRVConfig]: Parsed SRV configuration if present.

    Raises:
        ValueError: If SRV records are invalid.
    """
    if "srv" not in records:
        return None

    srv_section = _require_mapping(provider_id, "srv", records.get("srv"))
    _reject_unknown_keys(provider_id, "srv", srv_section, RECORD_SCHEMA["srv"]["section"])
    srv_required_raw = _require_mapping(
        provider_id, "srv required", srv_section.get("required", {})
    )
    srv_optional_raw = _require_mapping(
        provider_id, "srv optional", srv_section.get("optional", {})
    )
    srv_deprecated_raw = _require_mapping(
        provider_id, "srv deprecated", srv_section.get("deprecated", {})
    )
    srv_forbidden_raw = _require_mapping(
        provider_id, "srv forbidden", srv_section.get("forbidden", {})
    )
    srv_required = _parse_srv_records(provider_id, "srv required", srv_required_raw)
    srv_optional = _parse_srv_records(provider_id, "srv optional", srv_optional_raw)
    srv_deprecated = _parse_srv_match_rules(provider_id, "srv deprecated", srv_deprecated_raw)
    srv_forbidden = _parse_srv_match_rules(provider_id, "srv forbidden", srv_forbidden_raw)
    return SRVConfig(
        required=srv_required,
        optional=srv_optional,
        deprecated=srv_deprecated,
        forbidden=srv_forbidden,
    )
