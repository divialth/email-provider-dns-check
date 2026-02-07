"""Provider config parsing helpers."""

from __future__ import annotations

from typing import Dict

from ...models import ProviderConfig
from ...schema_validation import collect_provider_schema_errors
from ...utils import _reject_unknown_keys, _require_mapping
from .address import _parse_a, _parse_aaaa
from .caa import _parse_caa
from .cname import _parse_cname
from .dkim import _parse_dkim
from .dmarc import _parse_dmarc
from .metadata import _parse_provider_metadata
from .mx import _parse_mx
from .schema import RECORD_SCHEMA
from .spf import _parse_spf
from .srv import _parse_srv
from .txt import _parse_txt
from .variables import _parse_variables


def _raise_schema_validation_error(provider_id: str, data: dict) -> None:
    """Raise a normalized error for provider schema validation failures.

    Args:
        provider_id (str): Provider identifier used in error messages.
        data (dict): Provider payload to validate.

    Raises:
        ValueError: If schema validation errors are present.
    """
    errors = collect_provider_schema_errors(data)
    if not errors:
        return
    first_error = errors[0]
    raise ValueError(
        f"Provider config {provider_id} failed schema validation at "
        f"{first_error['location']}: {first_error['message']}"
    )


def _load_provider_from_data(provider_id: str, data: dict) -> ProviderConfig:
    """Load a ProviderConfig from resolved data.

    Args:
        provider_id (str): Provider identifier.
        data (dict): Resolved provider configuration mapping.

    Returns:
        ProviderConfig: Parsed provider configuration.

    Raises:
        ValueError: If the data is missing required fields or has invalid types.
    """
    version, provider_name, short_description, long_description = _parse_provider_metadata(
        provider_id, data
    )
    variables = _parse_variables(provider_id, data)
    if "records" in data:
        records = _require_mapping(provider_id, "records", data.get("records"))
    else:
        records = {}
    _reject_unknown_keys(
        provider_id,
        "records",
        records,
        RECORD_SCHEMA.keys(),
    )

    parsed = ProviderConfig(
        provider_id=provider_id,
        name=provider_name,
        version=version,
        short_description=short_description,
        long_description=long_description,
        mx=_parse_mx(provider_id, records),
        spf=_parse_spf(provider_id, records),
        dkim=_parse_dkim(provider_id, records),
        a=_parse_a(provider_id, records),
        aaaa=_parse_aaaa(provider_id, records),
        cname=_parse_cname(provider_id, records),
        caa=_parse_caa(provider_id, records),
        srv=_parse_srv(provider_id, records),
        txt=_parse_txt(provider_id, records),
        dmarc=_parse_dmarc(provider_id, records),
        variables=variables,
    )
    _raise_schema_validation_error(provider_id, data)
    return parsed
