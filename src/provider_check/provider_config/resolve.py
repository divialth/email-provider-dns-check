"""Resolve provider variables into concrete configurations."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .models import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    SPFConfig,
    SRVConfig,
    SRVRecord,
    TXTConfig,
)
from .utils import _format_string


def _format_list(values: Iterable[str], variables: Dict[str, str]) -> List[str]:
    """Format a list of values using provider variables.

    Args:
        values (Iterable[str]): Values to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        List[str]: Formatted values.
    """
    return [_format_string(value, variables) for value in values]


def _format_mapping(values: Dict[str, str], variables: Dict[str, str]) -> Dict[str, str]:
    """Format a mapping of string values using provider variables.

    Args:
        values (Dict[str, str]): Mapping to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, str]: Formatted mapping.
    """
    return {
        _format_string(key, variables): _format_string(value, variables)
        for key, value in values.items()
    }


def _format_list_mapping(
    values: Dict[str, Iterable[str]],
    variables: Dict[str, str],
) -> Dict[str, List[str]]:
    """Format a mapping of string lists using provider variables.

    Args:
        values (Dict[str, Iterable[str]]): Mapping of lists to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, List[str]]: Formatted mapping.
    """
    return {
        _format_string(name, variables): [_format_string(value, variables) for value in entries]
        for name, entries in values.items()
    }


def _format_caa_mapping(
    values: Dict[str, List[CAARecord]],
    variables: Dict[str, str],
) -> Dict[str, List[CAARecord]]:
    """Format a CAA records mapping using provider variables.

    Args:
        values (Dict[str, List[CAARecord]]): CAA mapping to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, List[CAARecord]]: Formatted CAA mapping.
    """
    formatted: Dict[str, List[CAARecord]] = {}
    for name, entries in values.items():
        formatted_name = _format_string(name, variables)
        formatted[formatted_name] = [
            CAARecord(
                flags=int(entry.flags),
                tag=str(_format_string(entry.tag, variables)),
                value=str(_format_string(entry.value, variables)),
            )
            for entry in entries
        ]
    return formatted


def _format_srv_mapping(
    values: Dict[str, List[SRVRecord]],
    variables: Dict[str, str],
) -> Dict[str, List[SRVRecord]]:
    """Format an SRV records mapping using provider variables.

    Args:
        values (Dict[str, List[SRVRecord]]): SRV mapping to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, List[SRVRecord]]: Formatted SRV mapping.
    """
    return {
        _format_string(name, variables): [
            SRVRecord(
                priority=int(entry.priority),
                weight=int(entry.weight),
                port=int(entry.port),
                target=_format_string(entry.target, variables),
            )
            for entry in entries
        ]
        for name, entries in values.items()
    }


def resolve_provider_config(
    provider: ProviderConfig, variables: Dict[str, str], *, domain: Optional[str] = None
) -> ProviderConfig:
    """Resolve provider variables into a concrete ProviderConfig.

    Args:
        provider (ProviderConfig): Base provider configuration.
        variables (Dict[str, str]): Provider variables supplied by the user.
        domain (Optional[str]): Domain to inject into template variables.

    Returns:
        ProviderConfig: Provider configuration with variables applied.

    Raises:
        ValueError: If unknown or required variables are missing.
    """
    if not provider.variables:
        if variables:
            allowed = ", ".join(sorted(provider.variables)) or "none"
            raise ValueError(
                f"Provider '{provider.provider_id}' does not accept variables. "
                f"Allowed variables: {allowed}"
            )
        return provider

    unknown = sorted(set(variables) - set(provider.variables))
    if unknown:
        allowed = ", ".join(sorted(provider.variables))
        unknown_list = ", ".join(unknown)
        raise ValueError(
            f"Unknown provider variable(s): {unknown_list}. Allowed variables: {allowed}"
        )

    resolved: Dict[str, str] = {}
    missing: List[str] = []
    for name, spec in provider.variables.items():
        if name in variables:
            resolved[name] = variables[name]
        elif spec.default is not None:
            resolved[name] = spec.default
        elif spec.required:
            missing.append(name)
    if missing:
        missing_list = ", ".join(missing)
        raise ValueError(
            f"Missing required provider variable(s): {missing_list}. "
            "Provide with --provider-var name=value."
        )

    if domain:
        resolved = dict(resolved)
        resolved["domain"] = domain

    if not resolved:
        return provider

    mx = None
    if provider.mx:
        mx = MXConfig(
            hosts=_format_list(provider.mx.hosts, resolved),
            priorities={
                _format_string(host, resolved): int(priority)
                for host, priority in provider.mx.priorities.items()
            },
        )

    spf = None
    if provider.spf:
        spf = SPFConfig(
            required_includes=_format_list(provider.spf.required_includes, resolved),
            strict_record=_format_string(provider.spf.strict_record, resolved),
            required_mechanisms=_format_list(provider.spf.required_mechanisms, resolved),
            allowed_mechanisms=_format_list(provider.spf.allowed_mechanisms, resolved),
            required_modifiers={
                key: _format_string(value, resolved)
                for key, value in provider.spf.required_modifiers.items()
            },
        )

    dkim = None
    if provider.dkim:
        dkim = DKIMConfig(
            selectors=_format_list(provider.dkim.selectors, resolved),
            record_type=provider.dkim.record_type,
            target_template=_format_string(provider.dkim.target_template, resolved),
            txt_values=_format_mapping(provider.dkim.txt_values, resolved),
        )

    a = None
    if provider.a:
        a = AddressConfig(
            records=_format_list_mapping(provider.a.records, resolved),
            records_optional=_format_list_mapping(provider.a.records_optional, resolved),
        )

    aaaa = None
    if provider.aaaa:
        aaaa = AddressConfig(
            records=_format_list_mapping(provider.aaaa.records, resolved),
            records_optional=_format_list_mapping(provider.aaaa.records_optional, resolved),
        )

    cname = None
    if provider.cname:
        cname = CNAMEConfig(
            records=_format_mapping(provider.cname.records, resolved),
            records_optional=_format_mapping(provider.cname.records_optional, resolved),
        )

    caa = None
    if provider.caa:
        caa_records = _format_caa_mapping(provider.caa.records, resolved)
        caa_optional_records = _format_caa_mapping(provider.caa.records_optional, resolved)
        caa = CAAConfig(records=caa_records, records_optional=caa_optional_records)

    srv = None
    if provider.srv:
        srv_records = _format_srv_mapping(provider.srv.records, resolved)
        srv_optional_records = _format_srv_mapping(provider.srv.records_optional, resolved)
        srv = SRVConfig(records=srv_records, records_optional=srv_optional_records)

    txt = None
    if provider.txt:
        required_txt = _format_list_mapping(provider.txt.records, resolved)
        optional_txt = _format_list_mapping(provider.txt.records_optional, resolved)
        txt = TXTConfig(
            records=required_txt,
            records_optional=optional_txt,
            verification_required=provider.txt.verification_required,
        )

    dmarc = None
    if provider.dmarc:
        dmarc = DMARCConfig(
            default_policy=_format_string(provider.dmarc.default_policy, resolved),
            required_rua=_format_list(provider.dmarc.required_rua, resolved),
            required_ruf=_format_list(provider.dmarc.required_ruf, resolved),
            required_tags={
                key: _format_string(value, resolved)
                for key, value in provider.dmarc.required_tags.items()
            },
            rua_required=provider.dmarc.rua_required,
            ruf_required=provider.dmarc.ruf_required,
        )

    return ProviderConfig(
        provider_id=provider.provider_id,
        name=provider.name,
        version=provider.version,
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
        short_description=provider.short_description,
        long_description=provider.long_description,
        variables=provider.variables,
    )
