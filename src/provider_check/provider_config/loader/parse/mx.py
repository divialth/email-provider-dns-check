"""MX record parsing."""

from __future__ import annotations

from typing import Dict

from ...models import MXConfig
from ...utils import _require_list, _require_mapping


def _parse_mx(provider_id: str, records: dict) -> MXConfig | None:
    """Parse MX config from records mapping.

    Args:
        provider_id (str): Provider identifier used in error messages.
        records (dict): Records mapping from provider config.

    Returns:
        Optional[MXConfig]: Parsed MX configuration if present.

    Raises:
        ValueError: If MX records are invalid.
    """
    if "mx" not in records:
        return None

    mx_section = _require_mapping(provider_id, "mx", records.get("mx"))
    hosts = _require_list(provider_id, "mx hosts", mx_section.get("hosts", []))
    priorities: Dict[str, int] = {}
    for entry in _require_list(provider_id, "mx records", mx_section.get("records", [])):
        if not isinstance(entry, dict):
            raise ValueError(f"Provider config {provider_id} mx records must be mappings")
        host = entry.get("host")
        priority = entry.get("priority")
        if host is None or priority is None:
            raise ValueError(f"Provider config {provider_id} mx records require host and priority")
        priorities[str(host)] = int(priority)
        if str(host) not in hosts:
            hosts.append(str(host))
    priorities_map = _require_mapping(
        provider_id, "mx priorities", mx_section.get("priorities", {})
    )
    for host, priority in priorities_map.items():
        priorities[str(host)] = int(priority)
        if str(host) not in hosts:
            hosts.append(str(host))
    return MXConfig(hosts=[str(host) for host in hosts], priorities=priorities)
