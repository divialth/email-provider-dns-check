"""Provider config variable parsing."""

from __future__ import annotations

from typing import Dict

from ...models import ProviderVariable
from ...utils import _RESERVED_VARIABLES, _reject_unknown_keys, _require_variables


def _parse_variables(provider_id: str, data: dict) -> Dict[str, ProviderVariable]:
    """Parse provider variables from config data.

    Args:
        provider_id (str): Provider identifier used in error messages.
        data (dict): Provider configuration mapping.

    Returns:
        Dict[str, ProviderVariable]: Parsed provider variables.

    Raises:
        ValueError: If variable definitions are invalid.
    """
    variables_section = _require_variables(provider_id, data.get("variables"))
    variables: Dict[str, ProviderVariable] = {}
    for key, spec in variables_section.items():
        if not isinstance(key, str):
            raise ValueError(
                f"Provider config {provider_id} variables must use string keys; got {key!r}"
            )
        var_name = key.strip()
        if not var_name:
            raise ValueError(f"Provider config {provider_id} variables keys must be non-empty")
        if var_name in _RESERVED_VARIABLES:
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' is reserved and cannot be used"
            )
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' must be a mapping"
            )
        _reject_unknown_keys(
            provider_id,
            f"variable '{var_name}'",
            spec,
            {"required", "default", "description"},
        )
        required = spec.get("required", False)
        if not isinstance(required, bool):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' required must be a boolean"
            )
        default = spec.get("default")
        if default is not None and not isinstance(default, str):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' default must be a string"
            )
        description = spec.get("description")
        if description is not None and not isinstance(description, str):
            raise ValueError(
                f"Provider config {provider_id} variable '{var_name}' description must be a string"
            )
        variables[var_name] = ProviderVariable(
            name=var_name,
            required=required,
            default=default,
            description=description,
        )
    return variables
