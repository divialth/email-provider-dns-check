"""Shared DMARC test support helpers."""

from __future__ import annotations

from provider_check.provider_config import (
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    ProviderConfig,
)


def make_dmarc_config(
    *,
    policy: str = "reject",
    required_rua: list[str] | None = None,
    required_ruf: list[str] | None = None,
    required_tags: dict[str, str] | None = None,
    rua_required: bool = False,
    ruf_required: bool = False,
) -> DMARCConfig:
    """Build a DMARC configuration for tests.

    Args:
        policy (str): Required DMARC policy value.
        required_rua (list[str] | None): Required aggregate report addresses.
        required_ruf (list[str] | None): Required forensic report addresses.
        required_tags (dict[str, str] | None): Required DMARC tags.
        rua_required (bool): Whether RUA is required.
        ruf_required (bool): Whether RUF is required.

    Returns:
        DMARCConfig: Test DMARC config.
    """
    return DMARCConfig(
        required=DMARCRequired(
            policy=policy,
            rua=required_rua or [],
            ruf=required_ruf or [],
            tags=required_tags or {},
        ),
        optional=DMARCOptional(rua=[], ruf=[]),
        settings=DMARCSettings(rua_required=rua_required, ruf_required=ruf_required),
    )


def make_provider_with_dmarc(
    dmarc: DMARCConfig | None,
    *,
    provider_id: str = "dmarc_provider",
    name: str = "DMARC Provider",
) -> ProviderConfig:
    """Build a provider config with a DMARC section.

    Args:
        dmarc (DMARCConfig | None): DMARC config to attach.
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
        spf=None,
        dkim=None,
        txt=None,
        dmarc=dmarc,
    )
