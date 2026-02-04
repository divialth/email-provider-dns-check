"""Provider config parsing helpers."""

from __future__ import annotations

from typing import Dict, List

from ..models import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    SRVConfig,
    SRVRecord,
    TXTConfig,
)
from ..utils import (
    _RESERVED_VARIABLES,
    _require_list,
    _require_mapping,
    _require_variables,
)


def _load_provider_from_data(provider_id: str, data: dict) -> ProviderConfig:
    """Load a ProviderConfig from resolved data.

    Args:
        provider_id (str): Provider identifier.
        data (dict): Resolved provider configuration mapping.

    Returns:
        ProviderConfig: Parsed provider configuration.

    Raises:
        ValueError: If the data is missing required fields or has invalid types.
    """
    version = data.get("version")
    if version is None:
        raise ValueError(f"Provider config {provider_id} is missing version")
    provider_name = data.get("name", provider_id)
    short_description = data.get("short_description")
    if short_description is not None and not isinstance(short_description, str):
        raise ValueError(f"Provider config {provider_id} short_description must be a string")
    long_description = data.get("long_description")
    if long_description is not None and not isinstance(long_description, str):
        raise ValueError(f"Provider config {provider_id} long_description must be a string")
    variables_section = _require_variables(provider_id, data.get("variables"))
    variables: Dict[str, ProviderVariable] = {}
    for key, spec in variables_section.items():
        if not isinstance(key, str):
            raise ValueError(
                f"Provider config {provider_id} variables must use string keys; got {key!r}"
            )
        var_name = key.strip()
        if not var_name:
            raise ValueError(f"Provider config {provider_id} variables keys must be non-empty")
        if var_name in _RESERVED_VARIABLES:
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' is reserved and cannot be used"
            )
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' must be a mapping"
            )
        required = spec.get("required", False)
        if not isinstance(required, bool):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' required must be a boolean"
            )
        default = spec.get("default")
        if default is not None and not isinstance(default, str):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' default must be a string"
            )
        description = spec.get("description")
        if description is not None and not isinstance(description, str):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' description must be a string"
            )
        variables[var_name] = ProviderVariable(
            name=var_name,
            required=required,
            default=default,
            description=description,
        )
    if "records" in data:
        records = _require_mapping(provider_id, "records", data.get("records"))
    else:
        records = {}

    mx = None
    if "mx" in records:
        mx_section = _require_mapping(provider_id, "mx", records.get("mx"))
        hosts = _require_list(provider_id, "mx hosts", mx_section.get("hosts", []))
        priorities: Dict[str, int] = {}
        for entry in _require_list(provider_id, "mx records", mx_section.get("records", [])):
            if not isinstance(entry, dict):
                raise ValueError(f"Provider config {provider_id} mx records must be mappings")
            host = entry.get("host")
            priority = entry.get("priority")
            if host is None or priority is None:
                raise ValueError(
                    f"Provider config {provider_id} mx records require host and priority"
                )
            priorities[str(host)] = int(priority)
            if str(host) not in hosts:
                hosts.append(str(host))
        priorities_map = _require_mapping(
            provider_id, "mx priorities", mx_section.get("priorities", {})
        )
        for host, priority in priorities_map.items():
            priorities[str(host)] = int(priority)
            if str(host) not in hosts:
                hosts.append(str(host))
        mx = MXConfig(hosts=[str(host) for host in hosts], priorities=priorities)

    spf = None
    if "spf" in records:
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
        spf = SPFConfig(
            required_includes=[str(value) for value in required],
            strict_record=spf_section.get("strict_record"),
            required_mechanisms=[str(value) for value in required_mechanisms],
            allowed_mechanisms=[str(value) for value in allowed_mechanisms],
            required_modifiers=required_modifiers,
        )

    dkim = None
    if "dkim" in records:
        dkim_section = _require_mapping(provider_id, "dkim", records.get("dkim"))
        selectors = _require_list(provider_id, "dkim selectors", dkim_section.get("selectors", []))
        record_type = str(dkim_section.get("record_type", "cname")).lower()
        if record_type not in {"cname", "txt"}:
            raise ValueError(f"Provider config {provider_id} dkim record_type must be cname or txt")
        target_template = dkim_section.get("target_template")
        if record_type == "cname" and not target_template:
            raise ValueError(
                f"Provider config {provider_id} dkim requires target_template for cname"
            )
        txt_values_raw = _require_mapping(
            provider_id, "dkim txt_values", dkim_section.get("txt_values", {})
        )
        txt_values = {str(key): str(value) for key, value in txt_values_raw.items()}
        dkim = DKIMConfig(
            selectors=[str(selector) for selector in selectors],
            record_type=record_type,
            target_template=str(target_template) if target_template else None,
            txt_values=txt_values,
        )

    def _parse_address_records(
        field_label: str, raw_records: Dict[str, object]
    ) -> Dict[str, List[str]]:
        """Parse A/AAAA record mappings.

        Args:
            field_label (str): Label used in error messages.
            raw_records (Dict[str, object]): Raw mapping of name to values.

        Returns:
            Dict[str, List[str]]: Parsed record mapping.

        Raises:
            ValueError: If any record values are invalid.
        """
        parsed: Dict[str, List[str]] = {}
        for name, values in raw_records.items():
            values_list = _require_list(provider_id, f"{field_label}.{name}", values)
            parsed[str(name)] = [str(value) for value in values_list]
        return parsed

    a = None
    if "a" in records:
        a_section = _require_mapping(provider_id, "a", records.get("a"))
        a_records_raw = _require_mapping(provider_id, "a records", a_section.get("records", {}))
        a_optional_raw = _require_mapping(
            provider_id, "a records_optional", a_section.get("records_optional", {})
        )
        a_records = _parse_address_records("a records", a_records_raw)
        a_optional_records = _parse_address_records("a records_optional", a_optional_raw)
        a = AddressConfig(records=a_records, records_optional=a_optional_records)

    aaaa = None
    if "aaaa" in records:
        aaaa_section = _require_mapping(provider_id, "aaaa", records.get("aaaa"))
        aaaa_records_raw = _require_mapping(
            provider_id, "aaaa records", aaaa_section.get("records", {})
        )
        aaaa_optional_raw = _require_mapping(
            provider_id, "aaaa records_optional", aaaa_section.get("records_optional", {})
        )
        aaaa_records = _parse_address_records("aaaa records", aaaa_records_raw)
        aaaa_optional_records = _parse_address_records("aaaa records_optional", aaaa_optional_raw)
        aaaa = AddressConfig(records=aaaa_records, records_optional=aaaa_optional_records)

    cname = None
    if "cname" in records:
        cname_section = _require_mapping(provider_id, "cname", records.get("cname"))
        cname_records_raw = _require_mapping(
            provider_id, "cname records", cname_section.get("records", {})
        )
        cname_optional_raw = _require_mapping(
            provider_id, "cname records_optional", cname_section.get("records_optional", {})
        )
        cname_records: Dict[str, str] = {}
        for name, target in cname_records_raw.items():
            if target is None or isinstance(target, (dict, list)):
                raise ValueError(
                    f"Provider config {provider_id} cname record '{name}' must be a string"
                )
            cname_records[str(name)] = str(target)
        cname_optional_records: Dict[str, str] = {}
        for name, target in cname_optional_raw.items():
            if target is None or isinstance(target, (dict, list)):
                raise ValueError(
                    f"Provider config {provider_id} cname records_optional '{name}' must be a string"
                )
            cname_optional_records[str(name)] = str(target)
        cname = CNAMEConfig(records=cname_records, records_optional=cname_optional_records)

    caa = None
    if "caa" in records:
        caa_section = _require_mapping(provider_id, "caa", records.get("caa"))
        caa_records_raw = _require_mapping(
            provider_id, "caa records", caa_section.get("records", {})
        )
        caa_optional_raw = _require_mapping(
            provider_id, "caa records_optional", caa_section.get("records_optional", {})
        )

        def _parse_caa_records(
            field_label: str, raw_records: Dict[str, object]
        ) -> Dict[str, List[CAARecord]]:
            """Parse a CAA records mapping.

            Args:
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
                    parsed_entries.append(
                        CAARecord(flags=int(flags), tag=str(tag), value=str(value))
                    )
                caa_records[str(name)] = parsed_entries
            return caa_records

        caa_records = _parse_caa_records("caa records", caa_records_raw)
        caa_optional_records = _parse_caa_records("caa records_optional", caa_optional_raw)
        caa = CAAConfig(records=caa_records, records_optional=caa_optional_records)

    srv = None
    if "srv" in records:
        srv_section = _require_mapping(provider_id, "srv", records.get("srv"))
        srv_records_raw = _require_mapping(
            provider_id, "srv records", srv_section.get("records", {})
        )
        srv_optional_raw = _require_mapping(
            provider_id, "srv records_optional", srv_section.get("records_optional", {})
        )
        srv_records: Dict[str, List[SRVRecord]] = {}
        for name, entries in srv_records_raw.items():
            entries_list = _require_list(provider_id, f"srv records.{name}", entries)
            parsed_entries: List[SRVRecord] = []
            for entry in entries_list:
                if not isinstance(entry, dict):
                    raise ValueError(
                        f"Provider config {provider_id} srv records.{name} entries must be mappings"
                    )
                priority = entry.get("priority")
                weight = entry.get("weight")
                port = entry.get("port")
                target = entry.get("target")
                if priority is None or weight is None or port is None or target is None:
                    raise ValueError(
                        f"Provider config {provider_id} srv records.{name} entries require priority, weight, port, and target"
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
        srv_optional_records: Dict[str, List[SRVRecord]] = {}
        for name, entries in srv_optional_raw.items():
            entries_list = _require_list(provider_id, f"srv records_optional.{name}", entries)
            parsed_entries: List[SRVRecord] = []
            for entry in entries_list:
                if not isinstance(entry, dict):
                    raise ValueError(
                        f"Provider config {provider_id} srv records_optional.{name} entries must be mappings"
                    )
                priority = entry.get("priority")
                weight = entry.get("weight")
                port = entry.get("port")
                target = entry.get("target")
                if priority is None or weight is None or port is None or target is None:
                    raise ValueError(
                        f"Provider config {provider_id} srv records_optional.{name} entries require priority, weight, port, and target"
                    )
                parsed_entries.append(
                    SRVRecord(
                        priority=int(priority),
                        weight=int(weight),
                        port=int(port),
                        target=str(target),
                    )
                )
            srv_optional_records[str(name)] = parsed_entries
        srv = SRVConfig(records=srv_records, records_optional=srv_optional_records)

    txt = None
    if "txt" in records:
        txt_section = _require_mapping(provider_id, "txt", records.get("txt"))
        required_raw = _require_mapping(
            provider_id, "txt required", txt_section.get("required", {})
        )
        required: Dict[str, List[str]] = {}
        for name, values in required_raw.items():
            values_list = _require_list(provider_id, f"txt required.{name}", values)
            required_values = [str(value) for value in values_list]
            required[str(name)] = required_values
        verification_required = txt_section.get("verification_required", False)
        if not isinstance(verification_required, bool):
            raise ValueError(
                f"Provider config {provider_id} txt verification_required must be a boolean"
            )
        txt = TXTConfig(required=required, verification_required=verification_required)

    dmarc = None
    if "dmarc" in records:
        dmarc_section = _require_mapping(provider_id, "dmarc", records.get("dmarc"))
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
        dmarc = DMARCConfig(
            default_policy=str(default_policy),
            required_rua=[str(value) for value in required_rua],
            required_ruf=[str(value) for value in required_ruf],
            required_tags=required_tags,
            rua_required=rua_required,
            ruf_required=ruf_required,
        )

    return ProviderConfig(
        provider_id=provider_id,
        name=str(provider_name),
        version=str(version),
        short_description=short_description,
        long_description=long_description,
        mx=mx,
        spf=spf,
        dkim=dkim,
        a=a,
        aaaa=aaaa,
        cname=cname,
        caa=caa,
        srv=srv,
        txt=txt,
        dmarc=dmarc,
        variables=variables,
    )
