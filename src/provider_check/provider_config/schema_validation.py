"""Shared JSON Schema validation for provider configuration payloads."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

_PROVIDER_SCHEMA_PACKAGE = "provider_check.resources.providers"
_PROVIDER_SCHEMA_FILENAME = "provider.schema.json"


@lru_cache(maxsize=1)
def _load_provider_schema_validator() -> Draft202012Validator:
    """Load and cache the provider JSON Schema validator.

    Returns:
        Draft202012Validator: Validator for provider YAML payloads.
    """
    schema_text = (
        resources.files(_PROVIDER_SCHEMA_PACKAGE)
        .joinpath(_PROVIDER_SCHEMA_FILENAME)
        .read_text(encoding="utf-8")
    )
    schema = json.loads(schema_text)
    return Draft202012Validator(schema)


def _schema_error_data(err: ValidationError) -> dict[str, str]:
    """Render one schema validation error as a structured mapping.

    Args:
        err (ValidationError): JSON Schema validation error.

    Returns:
        dict[str, str]: Error location and message fields.
    """
    location = ".".join(str(part) for part in err.absolute_path) or "<root>"
    return {"location": location, "message": str(err.message)}


def collect_provider_schema_errors(payload: object) -> list[dict[str, str]]:
    """Collect deterministic provider schema validation errors.

    Args:
        payload (object): Provider payload to validate.

    Returns:
        list[dict[str, str]]: Sorted schema validation errors.
    """
    validator = _load_provider_schema_validator()
    errors = [_schema_error_data(err) for err in validator.iter_errors(payload)]
    return sorted(errors, key=lambda item: (item["location"], item["message"]))
