"""Provider configuration package."""

from __future__ import annotations

from .loader import list_providers, load_provider_config, load_provider_config_data
from .models import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    SRVConfig,
    SRVRecord,
    TXTConfig,
)
from .resolve import resolve_provider_config
from .utils import CONFIG_DIR_NAME, PROVIDER_DIR_NAME, TEMPLATE_DIR_NAME, external_config_dirs

__all__ = [
    "AddressConfig",
    "CAAConfig",
    "CAARecord",
    "CNAMEConfig",
    "CONFIG_DIR_NAME",
    "DKIMConfig",
    "DMARCConfig",
    "MXConfig",
    "PROVIDER_DIR_NAME",
    "ProviderConfig",
    "ProviderVariable",
    "SPFConfig",
    "SRVConfig",
    "SRVRecord",
    "TEMPLATE_DIR_NAME",
    "TXTConfig",
    "external_config_dirs",
    "list_providers",
    "load_provider_config",
    "load_provider_config_data",
    "resolve_provider_config",
]
