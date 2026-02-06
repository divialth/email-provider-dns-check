"""Shared SPF test support helpers."""

from __future__ import annotations

from provider_check.provider_config import ProviderConfig, SPFConfig, SPFOptional, SPFRequired


def make_spf_config(
    *,
    required_record: str | None = None,
    includes: list[str] | None = None,
    required_mechanisms: list[str] | None = None,
    required_modifiers: dict[str, str] | None = None,
    optional_mechanisms: list[str] | None = None,
    optional_modifiers: dict[str, str] | None = None,
) -> SPFConfig:
    """Build an SPF config for tests.

    Args:
        required_record (str | None): Strict SPF record template.
        includes (list[str] | None): Required include mechanisms.
        required_mechanisms (list[str] | None): Required SPF mechanisms.
        required_modifiers (dict[str, str] | None): Required SPF modifiers.
        optional_mechanisms (list[str] | None): Allowed optional mechanisms.
        optional_modifiers (dict[str, str] | None): Allowed optional modifiers.

    Returns:
        SPFConfig: SPF config for checker tests.
    """
    return SPFConfig(
        required=SPFRequired(
            record=required_record,
            includes=includes or [],
            mechanisms=required_mechanisms or [],
            modifiers=required_modifiers or {},
        ),
        optional=SPFOptional(
            mechanisms=optional_mechanisms or [],
            modifiers=optional_modifiers or {},
        ),
    )


def make_provider_with_spf(
    spf: SPFConfig | None,
    *,
    provider_id: str = "spf_provider",
    name: str = "SPF Provider",
) -> ProviderConfig:
    """Build a provider config with an SPF section.

    Args:
        spf (SPFConfig | None): SPF config to attach.
        provider_id (str): Provider identifier.
        name (str): Human-readable provider name.

    Returns:
        ProviderConfig: Provider config for checker tests.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version="1",
        mx=None,
        spf=spf,
        dkim=None,
        txt=None,
        dmarc=None,
    )
