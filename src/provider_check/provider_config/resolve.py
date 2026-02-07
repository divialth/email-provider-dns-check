"""Resolve provider variables into concrete configurations."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from .models import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DKIMRequired,
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    MXConfig,
    MXRecord,
    PTRConfig,
    ProviderConfig,
    SPFConfig,
    SPFOptional,
    SPFRequired,
    SRVConfig,
    SRVRecord,
    TXTConfig,
    TXTSettings,
)
from .utils import _format_string

_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def _validate_allowed_placeholders(value: str, *, allowed: set[str], context: str) -> None:
    """Validate that a template contains only allowed unresolved placeholders.

    Args:
        value (str): Template string to validate.
        allowed (set[str]): Placeholder names that are allowed to remain unresolved.
        context (str): Error message context.

    Raises:
        ValueError: If disallowed placeholders are present.
    """
    placeholders = set(_PLACEHOLDER_RE.findall(value))
    disallowed = sorted(placeholders - allowed)
    if not disallowed:
        return
    allowed_values = ", ".join(sorted(allowed)) or "none"
    rendered = ", ".join(disallowed)
    raise ValueError(
        f"{context} contains unsupported placeholder(s): {rendered}. "
        f"Allowed unresolved placeholder(s): {allowed_values}."
    )


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


def _format_mx_records(values: List[MXRecord], variables: Dict[str, str]) -> List[MXRecord]:
    """Format MX record entries using provider variables.

    Args:
        values (List[MXRecord]): MX records to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        List[MXRecord]: Formatted MX records.
    """
    return [
        MXRecord(
            host=_format_string(entry.host, variables),
            priority=int(entry.priority) if entry.priority is not None else None,
        )
        for entry in values
    ]


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
            required=_format_mx_records(provider.mx.required, resolved),
            optional=_format_mx_records(provider.mx.optional, resolved),
        )

    spf = None
    if provider.spf:
        spf = SPFConfig(
            required=SPFRequired(
                policy=str(_format_string(provider.spf.required.policy, resolved)).lower(),
                includes=_format_list(provider.spf.required.includes, resolved),
                mechanisms=_format_list(provider.spf.required.mechanisms, resolved),
                modifiers=_format_mapping(provider.spf.required.modifiers, resolved),
            ),
            optional=SPFOptional(
                mechanisms=_format_list(provider.spf.optional.mechanisms, resolved),
                modifiers=_format_mapping(provider.spf.optional.modifiers, resolved),
            ),
        )

    dkim = None
    if provider.dkim:
        target_template = _format_string(provider.dkim.required.target_template, resolved)
        if target_template is not None:
            _validate_allowed_placeholders(
                target_template,
                allowed={"selector"},
                context=f"Provider '{provider.provider_id}' DKIM target_template",
            )
        dkim = DKIMConfig(
            required=DKIMRequired(
                selectors=_format_list(provider.dkim.required.selectors, resolved),
                record_type=provider.dkim.required.record_type,
                target_template=target_template,
                txt_values=_format_mapping(provider.dkim.required.txt_values, resolved),
            )
        )

    a = None
    if provider.a:
        a = AddressConfig(
            required=_format_list_mapping(provider.a.required, resolved),
            optional=_format_list_mapping(provider.a.optional, resolved),
        )

    aaaa = None
    if provider.aaaa:
        aaaa = AddressConfig(
            required=_format_list_mapping(provider.aaaa.required, resolved),
            optional=_format_list_mapping(provider.aaaa.optional, resolved),
        )

    ptr = None
    if provider.ptr:
        ptr = PTRConfig(
            required=_format_list_mapping(provider.ptr.required, resolved),
            optional=_format_list_mapping(provider.ptr.optional, resolved),
        )

    cname = None
    if provider.cname:
        cname = CNAMEConfig(
            required=_format_mapping(provider.cname.required, resolved),
            optional=_format_mapping(provider.cname.optional, resolved),
        )

    caa = None
    if provider.caa:
        caa_required = _format_caa_mapping(provider.caa.required, resolved)
        caa_optional = _format_caa_mapping(provider.caa.optional, resolved)
        caa = CAAConfig(required=caa_required, optional=caa_optional)

    srv = None
    if provider.srv:
        srv_required = _format_srv_mapping(provider.srv.required, resolved)
        srv_optional = _format_srv_mapping(provider.srv.optional, resolved)
        srv = SRVConfig(required=srv_required, optional=srv_optional)

    txt = None
    if provider.txt:
        required_txt = _format_list_mapping(provider.txt.required, resolved)
        optional_txt = _format_list_mapping(provider.txt.optional, resolved)
        txt = TXTConfig(
            required=required_txt,
            optional=optional_txt,
            settings=TXTSettings(verification_required=provider.txt.settings.verification_required),
        )

    dmarc = None
    if provider.dmarc:
        dmarc = DMARCConfig(
            required=DMARCRequired(
                policy=_format_string(provider.dmarc.required.policy, resolved),
                rua=_format_list(provider.dmarc.required.rua, resolved),
                ruf=_format_list(provider.dmarc.required.ruf, resolved),
                tags=_format_mapping(provider.dmarc.required.tags, resolved),
            ),
            optional=DMARCOptional(
                rua=_format_list(provider.dmarc.optional.rua, resolved),
                ruf=_format_list(provider.dmarc.optional.ruf, resolved),
            ),
            settings=DMARCSettings(
                rua_required=provider.dmarc.settings.rua_required,
                ruf_required=provider.dmarc.settings.ruf_required,
            ),
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
        ptr=ptr,
        cname=cname,
        caa=caa,
        srv=srv,
        txt=txt,
        dmarc=dmarc,
        short_description=provider.short_description,
        long_description=provider.long_description,
        variables=provider.variables,
    )
