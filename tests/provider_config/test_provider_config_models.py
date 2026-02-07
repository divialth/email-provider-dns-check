"""Model-level tests for provider configuration dataclasses."""

from __future__ import annotations

import pytest

from provider_check.provider_config import ProviderConfig


def test_provider_config_requires_keyword_arguments() -> None:
    """Reject positional construction for ``ProviderConfig``."""
    with pytest.raises(TypeError):
        ProviderConfig("provider", "Provider", "1", None, None, None)


def test_provider_config_keyword_construction() -> None:
    """Allow keyword-based construction for ``ProviderConfig``."""
    config = ProviderConfig(
        provider_id="provider",
        name="Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
    )

    assert config.provider_id == "provider"
