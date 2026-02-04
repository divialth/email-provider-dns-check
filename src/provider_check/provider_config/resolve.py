"""Resolve provider variables into concrete configurations."""

from __future__ import annotations

from typing import Dict, List, Optional

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
            hosts=[_format_string(host, resolved) for host in provider.mx.hosts],
            priorities={
                _format_string(host, resolved): int(priority)
                for host, priority in provider.mx.priorities.items()
            },
        )

    spf = None
    if provider.spf:
        spf = SPFConfig(
            required_includes=[
                _format_string(value, resolved) for value in provider.spf.required_includes
            ],
            strict_record=_format_string(provider.spf.strict_record, resolved),
            required_mechanisms=[
                _format_string(value, resolved) for value in provider.spf.required_mechanisms
            ],
            allowed_mechanisms=[
                _format_string(value, resolved) for value in provider.spf.allowed_mechanisms
            ],
            required_modifiers={
                key: _format_string(value, resolved)
                for key, value in provider.spf.required_modifiers.items()
            },
        )

    dkim = None
    if provider.dkim:
        dkim = DKIMConfig(
            selectors=[_format_string(selector, resolved) for selector in provider.dkim.selectors],
            record_type=provider.dkim.record_type,
            target_template=_format_string(provider.dkim.target_template, resolved),
            txt_values={
                _format_string(key, resolved): _format_string(value, resolved)
                for key, value in provider.dkim.txt_values.items()
            },
        )

    a = None
    if provider.a:
        a = AddressConfig(
            records={
                _format_string(name, resolved): [
                    _format_string(value, resolved) for value in values
                ]
                for name, values in provider.a.records.items()
            },
            records_optional={
                _format_string(name, resolved): [
                    _format_string(value, resolved) for value in values
                ]
                for name, values in provider.a.records_optional.items()
            },
        )

    aaaa = None
    if provider.aaaa:
        aaaa = AddressConfig(
            records={
                _format_string(name, resolved): [
                    _format_string(value, resolved) for value in values
                ]
                for name, values in provider.aaaa.records.items()
            },
            records_optional={
                _format_string(name, resolved): [
                    _format_string(value, resolved) for value in values
                ]
                for name, values in provider.aaaa.records_optional.items()
            },
        )

    cname = None
    if provider.cname:
        cname = CNAMEConfig(
            records={
                _format_string(name, resolved): _format_string(target, resolved)
                for name, target in provider.cname.records.items()
            },
            records_optional={
                _format_string(name, resolved): _format_string(target, resolved)
                for name, target in provider.cname.records_optional.items()
            },
        )

    caa = None
    if provider.caa:
        caa_records: Dict[str, List[CAARecord]] = {}
        for name, entries in provider.caa.records.items():
            formatted_name = _format_string(name, resolved)
            caa_records[formatted_name] = [
                CAARecord(
                    flags=int(entry.flags),
                    tag=str(_format_string(entry.tag, resolved)),
                    value=str(_format_string(entry.value, resolved)),
                )
                for entry in entries
            ]
        caa_optional_records: Dict[str, List[CAARecord]] = {}
        for name, entries in provider.caa.records_optional.items():
            formatted_name = _format_string(name, resolved)
            caa_optional_records[formatted_name] = [
                CAARecord(
                    flags=int(entry.flags),
                    tag=str(_format_string(entry.tag, resolved)),
                    value=str(_format_string(entry.value, resolved)),
                )
                for entry in entries
            ]
        caa = CAAConfig(records=caa_records, records_optional=caa_optional_records)

    srv = None
    if provider.srv:
        srv_records: Dict[str, List[SRVRecord]] = {}
        for name, entries in provider.srv.records.items():
            srv_records[_format_string(name, resolved)] = [
                SRVRecord(
                    priority=int(entry.priority),
                    weight=int(entry.weight),
                    port=int(entry.port),
                    target=_format_string(entry.target, resolved),
                )
                for entry in entries
            ]
        srv_optional_records: Dict[str, List[SRVRecord]] = {}
        for name, entries in provider.srv.records_optional.items():
            srv_optional_records[_format_string(name, resolved)] = [
                SRVRecord(
                    priority=int(entry.priority),
                    weight=int(entry.weight),
                    port=int(entry.port),
                    target=_format_string(entry.target, resolved),
                )
                for entry in entries
            ]
        srv = SRVConfig(records=srv_records, records_optional=srv_optional_records)

    txt = None
    if provider.txt:
        required_txt: Dict[str, List[str]] = {}
        for name, values in provider.txt.required.items():
            formatted_name = _format_string(name, resolved)
            required_txt[formatted_name] = [_format_string(value, resolved) for value in values]
        txt = TXTConfig(
            required=required_txt,
            verification_required=provider.txt.verification_required,
        )

    dmarc = None
    if provider.dmarc:
        dmarc = DMARCConfig(
            default_policy=_format_string(provider.dmarc.default_policy, resolved),
            required_rua=[_format_string(value, resolved) for value in provider.dmarc.required_rua],
            required_ruf=[_format_string(value, resolved) for value in provider.dmarc.required_ruf],
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
