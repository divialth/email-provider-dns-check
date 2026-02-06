"""Shared test factories."""

from __future__ import annotations

from provider_check.checker import RecordCheck
from provider_check.provider_config import ProviderConfig, ProviderVariable
from provider_check.status import Status


def make_provider_config(
    *,
    provider_id: str = "dummy",
    name: str = "Dummy Provider",
    version: str = "1",
    variables: dict[str, ProviderVariable] | None = None,
    short_description: str | None = None,
    long_description: str | None = None,
) -> ProviderConfig:
    """Build a minimal provider config for tests.

    Args:
        provider_id (str): Provider identifier.
        name (str): Human readable provider name.
        version (str): Provider config version.
        variables (dict[str, ProviderVariable] | None): Optional provider variable mapping.
        short_description (str | None): Optional short provider description.
        long_description (str | None): Optional long provider description.

    Returns:
        ProviderConfig: Minimal provider configuration object.
    """
    return ProviderConfig(
        provider_id=provider_id,
        name=name,
        version=version,
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        variables=variables,
        short_description=short_description,
        long_description=long_description,
    )


def make_record_check(
    *,
    record_type: str = "MX",
    status: Status = Status.PASS,
    message: str = "ok",
    details: dict[str, object] | None = None,
    optional: bool = False,
) -> RecordCheck:
    """Build a record-check result object for tests.

    Args:
        record_type (str): DNS record type for the check.
        status (Status): Status value for the record check.
        message (str): Human-readable check message.
        details (dict[str, object] | None): Optional details payload.
        optional (bool): Whether the record check is optional.

    Returns:
        RecordCheck: Record-check model for assertions and mocked results.
    """
    return RecordCheck.with_status(
        record_type,
        status,
        message,
        details or {"found": ["mx"]},
        optional=optional,
    )
