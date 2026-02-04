"""TXT record parsing."""

from __future__ import annotations

from typing import Dict, List

from ...models import TXTConfig
from ...utils import _require_list, _require_mapping


def _parse_txt(provider_id: str, records: dict) -> TXTConfig | None:
    """Parse TXT config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[TXTConfig]: Parsed TXT configuration if present.

    Raises:
        ValueError: If TXT records are invalid.
    """
    if "txt" not in records:
        return None

    txt_section = _require_mapping(provider_id, "txt", records.get("txt"))
    required_raw = _require_mapping(provider_id, "txt required", txt_section.get("required", {}))
    required: Dict[str, List[str]] = {}
    for name, values in required_raw.items():
        values_list = _require_list(provider_id, f"txt required.{name}", values)
        required_values = [str(value) for value in values_list]
        required[str(name)] = required_values
    verification_required = txt_section.get("verification_required", False)
    if not isinstance(verification_required, bool):
        raise ValueError(
            f"Provider config {provider_id} txt verification_required must be a boolean"
        )
    return TXTConfig(required=required, verification_required=verification_required)
