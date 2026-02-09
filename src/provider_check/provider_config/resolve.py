"""Resolve provider variables into concrete configurations."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from .models import (
    AddressConfig,
    CAAMatchRule,
    CAAConfig,
    CAARecord,
    CNAMEMatchRule,
    CNAMEConfig,
    DKIMConfig,
    DKIMRequired,
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    MXConfig,
    MXNegativePolicy,
    MXNegativeRules,
    MXRecord,
    PTRConfig,
    ProviderConfig,
    SPFConfig,
    SPFOptional,
    SPFRequired,
    SRVMatchRule,
    SRVConfig,
    SRVRecord,
    TLSAMatchRule,
    TLSAConfig,
    TLSARecord,
    TXTConfig,
    TXTSettings,
    ValuesMatchRule,
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


def _format_cname_match_rules(
    values: Dict[str, CNAMEMatchRule], variables: Dict[str, str]
) -> Dict[str, CNAMEMatchRule]:
    """Format CNAME match rules using provider variables.

    Args:
        values (Dict[str, CNAMEMatchRule]): CNAME match rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, CNAMEMatchRule]: Formatted CNAME match rules.
    """
    return {
        _format_string(name, variables): CNAMEMatchRule(
            match=str(rule.match),
            target=_format_string(rule.target, variables),
        )
        for name, rule in values.items()
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


def _format_values_match_rules(
    values: Dict[str, ValuesMatchRule], variables: Dict[str, str]
) -> Dict[str, ValuesMatchRule]:
    """Format list-valued match rules using provider variables.

    Args:
        values (Dict[str, ValuesMatchRule]): Match rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, ValuesMatchRule]: Formatted match rules.
    """
    return {
        _format_string(name, variables): ValuesMatchRule(
            match=str(rule.match),
            values=[_format_string(value, variables) for value in rule.values],
        )
        for name, rule in values.items()
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


def _format_caa_match_rules(
    values: Dict[str, CAAMatchRule], variables: Dict[str, str]
) -> Dict[str, CAAMatchRule]:
    """Format CAA match rules using provider variables.

    Args:
        values (Dict[str, CAAMatchRule]): CAA match rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, CAAMatchRule]: Formatted CAA match rules.
    """
    formatted: Dict[str, CAAMatchRule] = {}
    for name, rule in values.items():
        formatted_name = _format_string(name, variables)
        formatted_entries = [
            CAARecord(
                flags=int(entry.flags),
                tag=str(_format_string(entry.tag, variables)),
                value=str(_format_string(entry.value, variables)),
            )
            for entry in rule.entries
        ]
        formatted[formatted_name] = CAAMatchRule(match=str(rule.match), entries=formatted_entries)
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


def _format_srv_match_rules(
    values: Dict[str, SRVMatchRule], variables: Dict[str, str]
) -> Dict[str, SRVMatchRule]:
    """Format SRV match rules using provider variables.

    Args:
        values (Dict[str, SRVMatchRule]): SRV match rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, SRVMatchRule]: Formatted SRV match rules.
    """
    return {
        _format_string(name, variables): SRVMatchRule(
            match=str(rule.match),
            entries=[
                SRVRecord(
                    priority=int(entry.priority),
                    weight=int(entry.weight),
                    port=int(entry.port),
                    target=_format_string(entry.target, variables),
                )
                for entry in rule.entries
            ],
        )
        for name, rule in values.items()
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


def _format_mx_negative_rules(rules: MXNegativeRules, variables: Dict[str, str]) -> MXNegativeRules:
    """Format MX negative rules using provider variables.

    Args:
        rules (MXNegativeRules): MX negative rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        MXNegativeRules: Formatted MX negative rules.
    """
    return MXNegativeRules(
        policy=MXNegativePolicy(match=str(rules.policy.match)),
        entries=_format_mx_records(rules.entries, variables),
    )


def _format_tlsa_mapping(
    values: Dict[str, List[TLSARecord]],
    variables: Dict[str, str],
) -> Dict[str, List[TLSARecord]]:
    """Format a TLSA records mapping using provider variables.

    Args:
        values (Dict[str, List[TLSARecord]]): TLSA mapping to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, List[TLSARecord]]: Formatted TLSA mapping.
    """
    return {
        _format_string(name, variables): [
            TLSARecord(
                usage=int(entry.usage),
                selector=int(entry.selector),
                matching_type=int(entry.matching_type),
                certificate_association=_format_string(entry.certificate_association, variables),
            )
            for entry in entries
        ]
        for name, entries in values.items()
    }


def _format_tlsa_match_rules(
    values: Dict[str, TLSAMatchRule], variables: Dict[str, str]
) -> Dict[str, TLSAMatchRule]:
    """Format TLSA match rules using provider variables.

    Args:
        values (Dict[str, TLSAMatchRule]): TLSA match rules to format.
        variables (Dict[str, str]): Provider variables.

    Returns:
        Dict[str, TLSAMatchRule]: Formatted TLSA match rules.
    """
    return {
        _format_string(name, variables): TLSAMatchRule(
            match=str(rule.match),
            entries=[
                TLSARecord(
                    usage=int(entry.usage),
                    selector=int(entry.selector),
                    matching_type=int(entry.matching_type),
                    certificate_association=_format_string(
                        entry.certificate_association, variables
                    ),
                )
                for entry in rule.entries
            ],
        )
        for name, rule in values.items()
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
            required=_format_mx_records(provider.mx.required, resolved),
            optional=_format_mx_records(provider.mx.optional, resolved),
            deprecated=_format_mx_negative_rules(provider.mx.deprecated, resolved),
            forbidden=_format_mx_negative_rules(provider.mx.forbidden, resolved),
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
            deprecated=_format_values_match_rules(provider.a.deprecated, resolved),
            forbidden=_format_values_match_rules(provider.a.forbidden, resolved),
        )

    aaaa = None
    if provider.aaaa:
        aaaa = AddressConfig(
            required=_format_list_mapping(provider.aaaa.required, resolved),
            optional=_format_list_mapping(provider.aaaa.optional, resolved),
            deprecated=_format_values_match_rules(provider.aaaa.deprecated, resolved),
            forbidden=_format_values_match_rules(provider.aaaa.forbidden, resolved),
        )

    ptr = None
    if provider.ptr:
        ptr = PTRConfig(
            required=_format_list_mapping(provider.ptr.required, resolved),
            optional=_format_list_mapping(provider.ptr.optional, resolved),
            deprecated=_format_values_match_rules(provider.ptr.deprecated, resolved),
            forbidden=_format_values_match_rules(provider.ptr.forbidden, resolved),
        )

    cname = None
    if provider.cname:
        cname = CNAMEConfig(
            required=_format_mapping(provider.cname.required, resolved),
            optional=_format_mapping(provider.cname.optional, resolved),
            deprecated=_format_cname_match_rules(provider.cname.deprecated, resolved),
            forbidden=_format_cname_match_rules(provider.cname.forbidden, resolved),
        )

    caa = None
    if provider.caa:
        caa_required = _format_caa_mapping(provider.caa.required, resolved)
        caa_optional = _format_caa_mapping(provider.caa.optional, resolved)
        caa_deprecated = _format_caa_match_rules(provider.caa.deprecated, resolved)
        caa_forbidden = _format_caa_match_rules(provider.caa.forbidden, resolved)
        caa = CAAConfig(
            required=caa_required,
            optional=caa_optional,
            deprecated=caa_deprecated,
            forbidden=caa_forbidden,
        )

    srv = None
    if provider.srv:
        srv_required = _format_srv_mapping(provider.srv.required, resolved)
        srv_optional = _format_srv_mapping(provider.srv.optional, resolved)
        srv_deprecated = _format_srv_match_rules(provider.srv.deprecated, resolved)
        srv_forbidden = _format_srv_match_rules(provider.srv.forbidden, resolved)
        srv = SRVConfig(
            required=srv_required,
            optional=srv_optional,
            deprecated=srv_deprecated,
            forbidden=srv_forbidden,
        )

    tlsa = None
    if provider.tlsa:
        tlsa_required = _format_tlsa_mapping(provider.tlsa.required, resolved)
        tlsa_optional = _format_tlsa_mapping(provider.tlsa.optional, resolved)
        tlsa_deprecated = _format_tlsa_match_rules(provider.tlsa.deprecated, resolved)
        tlsa_forbidden = _format_tlsa_match_rules(provider.tlsa.forbidden, resolved)
        tlsa = TLSAConfig(
            required=tlsa_required,
            optional=tlsa_optional,
            deprecated=tlsa_deprecated,
            forbidden=tlsa_forbidden,
        )

    txt = None
    if provider.txt:
        required_txt = _format_list_mapping(provider.txt.required, resolved)
        optional_txt = _format_list_mapping(provider.txt.optional, resolved)
        deprecated_txt = _format_values_match_rules(provider.txt.deprecated, resolved)
        forbidden_txt = _format_values_match_rules(provider.txt.forbidden, resolved)
        txt = TXTConfig(
            required=required_txt,
            optional=optional_txt,
            deprecated=deprecated_txt,
            forbidden=forbidden_txt,
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
        tlsa=tlsa,
        txt=txt,
        dmarc=dmarc,
        short_description=provider.short_description,
        long_description=provider.long_description,
        variables=provider.variables,
    )
