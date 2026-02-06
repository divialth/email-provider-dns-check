"""Shared MX test support helpers."""

from __future__ import annotations

from provider_check.provider_config import MXConfig, MXRecord, ProviderConfig


def make_mx_config(
    *,
    required: list[MXRecord] | None = None,
    optional: list[MXRecord] | None = None,
) -> MXConfig:
    """Build an MX config for tests.

    Args:
        required (list[MXRecord] | None): Required MX records.
        optional (list[MXRecord] | None): Optional MX records.

    Returns:
        MXConfig: MX config object.
    """
    return MXConfig(required=required or [], optional=optional or [])


def make_provider_with_mx(
    mx: MXConfig | None,
    *,
    provider_id: str = "mx_provider",
    name: str = "MX Provider",
) -> ProviderConfig:
    """Build a provider config with an MX section.

    Args:
        mx (MXConfig | None): MX config to attach.
        provider_id (str): Provider identifier.
        name (str): Human-readable provider name.

    Returns:
        ProviderConfig: Provider config for MX checker tests.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version="1",
        mx=mx,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
