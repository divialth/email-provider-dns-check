"""Shared TLSA test support helpers."""

from __future__ import annotations

from provider_check.provider_config import ProviderConfig, TLSAConfig, TLSARecord


def make_tlsa_config(
    required: dict[str, list[TLSARecord]] | None = None,
    optional: dict[str, list[TLSARecord]] | None = None,
) -> TLSAConfig:
    """Build a TLSA config for tests.

    Args:
        required (dict[str, list[TLSARecord]] | None): Required TLSA records by name.
        optional (dict[str, list[TLSARecord]] | None): Optional TLSA records by name.

    Returns:
        TLSAConfig: TLSA config model.
    """
    return TLSAConfig(required=required or {}, optional=optional or {})


def make_provider_with_tlsa(
    tlsa: TLSAConfig | None,
    provider_id: str = "tlsa_provider",
    name: str = "TLSA Provider",
) -> ProviderConfig:
    """Build a provider config with a TLSA section.

    Args:
        tlsa (TLSAConfig | None): TLSA config to attach.
        provider_id (str): Provider identifier.
        name (str): Provider display name.

    Returns:
        ProviderConfig: Provider config for TLSA checker tests.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        tlsa=tlsa,
        txt=None,
        dmarc=None,
    )
