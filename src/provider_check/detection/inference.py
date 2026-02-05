"""Inference helpers for provider detection."""

from __future__ import annotations

import logging
from typing import Dict

from ..dns_resolver import DnsLookupError, DnsResolver
from ..provider_config import ProviderConfig
from .utils import (
    _match_and_infer,
    _normalize_host,
    _normalize_host_template,
    _normalize_record_name,
)

LOGGER = logging.getLogger(__name__)


def _infer_from_mx(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    """Infer provider variables from MX records.

    Args:
        provider (ProviderConfig): Provider configuration.
        domain (str): Domain to inspect.
        resolver (DnsResolver): DNS resolver for lookups.
        known_vars (Dict[str, str]): Variables with fixed values.
        inferred_vars (Dict[str, str]): Output mapping to update in place.
    """
    if not provider.mx:
        return
    try:
        mx_records = resolver.get_mx(domain)
    except DnsLookupError as err:
        LOGGER.debug("MX lookup failed during detection for %s: %s", domain, err)
        return
    samples = [_normalize_host(host) for host, _pref in mx_records]
    templates = [
        _normalize_host_template(entry.host)
        for entry in [*provider.mx.required, *provider.mx.optional]
    ]
    for template in templates:
        _match_and_infer(template, samples, known_vars, inferred_vars, provider.variables)


def _infer_from_dkim(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    """Infer provider variables from DKIM CNAME records.

    Args:
        provider (ProviderConfig): Provider configuration.
        domain (str): Domain to inspect.
        resolver (DnsResolver): DNS resolver for lookups.
        known_vars (Dict[str, str]): Variables with fixed values.
        inferred_vars (Dict[str, str]): Output mapping to update in place.
    """
    if not provider.dkim or provider.dkim.required.record_type != "cname":
        return
    template = provider.dkim.required.target_template
    if not template:
        return
    for selector in provider.dkim.required.selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            target = resolver.get_cname(name)
        except DnsLookupError as err:
            LOGGER.debug("DKIM CNAME lookup failed during detection for %s: %s", name, err)
            continue
        if not target:
            continue
        selector_vars = dict(known_vars)
        selector_vars["selector"] = selector.lower()
        normalized_template = _normalize_host_template(template)
        normalized_target = _normalize_host(target)
        _match_and_infer(
            normalized_template,
            [normalized_target],
            selector_vars,
            inferred_vars,
            provider.variables,
        )


def _infer_from_cname(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    """Infer provider variables from CNAME records.

    Args:
        provider (ProviderConfig): Provider configuration.
        domain (str): Domain to inspect.
        resolver (DnsResolver): DNS resolver for lookups.
        known_vars (Dict[str, str]): Variables with fixed values.
        inferred_vars (Dict[str, str]): Output mapping to update in place.
    """
    if not provider.cname:
        return
    for name, target_template in provider.cname.required.items():
        lookup_name = _normalize_record_name(name, domain)
        if "{" in lookup_name or "}" in lookup_name:
            continue
        try:
            target = resolver.get_cname(lookup_name)
        except DnsLookupError as err:
            LOGGER.debug("CNAME lookup failed during detection for %s: %s", lookup_name, err)
            continue
        if not target:
            continue
        normalized_template = _normalize_host_template(target_template)
        normalized_target = _normalize_host(target)
        _match_and_infer(
            normalized_template,
            [normalized_target],
            known_vars,
            inferred_vars,
            provider.variables,
        )


def _infer_from_srv(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    """Infer provider variables from SRV records.

    Args:
        provider (ProviderConfig): Provider configuration.
        domain (str): Domain to inspect.
        resolver (DnsResolver): DNS resolver for lookups.
        known_vars (Dict[str, str]): Variables with fixed values.
        inferred_vars (Dict[str, str]): Output mapping to update in place.
    """
    if not provider.srv:
        return
    for name, entries in provider.srv.required.items():
        lookup_name = _normalize_record_name(name, domain)
        if "{" in lookup_name or "}" in lookup_name:
            continue
        try:
            found_entries = resolver.get_srv(lookup_name)
        except DnsLookupError as err:
            LOGGER.debug("SRV lookup failed during detection for %s: %s", lookup_name, err)
            continue
        targets = [_normalize_host(target) for _pri, _weight, _port, target in found_entries]
        for entry in entries:
            normalized_template = _normalize_host_template(entry.target)
            _match_and_infer(
                normalized_template,
                targets,
                known_vars,
                inferred_vars,
                provider.variables,
            )


def infer_provider_variables(
    provider: ProviderConfig, domain: str, resolver: DnsResolver
) -> Dict[str, str]:
    """Infer provider variables based on DNS records.

    Args:
        provider (ProviderConfig): Provider configuration.
        domain (str): Domain to inspect.
        resolver (DnsResolver): DNS resolver for lookups.

    Returns:
        Dict[str, str]: Mapping of inferred variable values.
    """
    if not provider.variables:
        return {}
    known_vars = {"domain": domain.lower().strip()}
    inferred: Dict[str, str] = {}
    _infer_from_mx(provider, domain, resolver, known_vars, inferred)
    _infer_from_dkim(provider, domain, resolver, known_vars, inferred)
    _infer_from_cname(provider, domain, resolver, known_vars, inferred)
    _infer_from_srv(provider, domain, resolver, known_vars, inferred)
    return inferred
