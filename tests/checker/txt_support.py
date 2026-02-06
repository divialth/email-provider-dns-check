"""Shared TXT test support helpers."""

from __future__ import annotations

from provider_check.provider_config import ProviderConfig, TXTConfig, TXTSettings


def make_txt_config(
    *,
    required: dict[str, list[str]] | None = None,
    optional: dict[str, list[str]] | None = None,
    verification_required: bool = False,
) -> TXTConfig:
    """Build a TXT config for tests.

    Args:
        required (dict[str, list[str]] | None): Required TXT values by name.
        optional (dict[str, list[str]] | None): Optional TXT values by name.
        verification_required (bool): Whether user verification TXT is required.

    Returns:
        TXTConfig: TXT config model.
    """
    return TXTConfig(
        required=required or {},
        optional=optional or {},
        settings=TXTSettings(verification_required=verification_required),
    )


def make_provider_with_txt(
    txt: TXTConfig | None,
    *,
    provider_id: str = "txt_provider",
    name: str = "TXT Provider",
) -> ProviderConfig:
    """Build a provider config with a TXT section.

    Args:
        txt (TXTConfig | None): TXT config to attach.
        provider_id (str): Provider identifier.
        name (str): Human-readable provider name.

    Returns:
        ProviderConfig: Provider config for TXT checker tests.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=txt,
        dmarc=None,
    )
