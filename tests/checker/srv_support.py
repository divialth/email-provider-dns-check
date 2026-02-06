"""Shared SRV test support helpers."""

from __future__ import annotations

from provider_check.provider_config import ProviderConfig, SRVConfig, SRVRecord


def make_srv_config(
    *,
    required: dict[str, list[SRVRecord]] | None = None,
    optional: dict[str, list[SRVRecord]] | None = None,
) -> SRVConfig:
    """Build an SRV config for tests.

    Args:
        required (dict[str, list[SRVRecord]] | None): Required SRV records by name.
        optional (dict[str, list[SRVRecord]] | None): Optional SRV records by name.

    Returns:
        SRVConfig: SRV config model.
    """
    return SRVConfig(required=required or {}, optional=optional or {})


def make_provider_with_srv(
    srv: SRVConfig | None,
    *,
    provider_id: str = "srv_provider",
    name: str = "SRV Provider",
) -> ProviderConfig:
    """Build a provider config with an SRV section.

    Args:
        srv (SRVConfig | None): SRV config to attach.
        provider_id (str): Provider identifier.
        name (str): Human-readable provider name.

    Returns:
        ProviderConfig: Provider config for SRV checker tests.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        srv=srv,
        txt=None,
        dmarc=None,
    )
