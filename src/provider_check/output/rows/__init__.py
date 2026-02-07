"""Row builders for output rendering."""

from __future__ import annotations

from typing import Dict, List

from ...record_registry import ROW_BUILDER_NAMES
from .address import _build_address_rows
from .caa import _build_caa_rows, _format_caa_entry
from .cname import _build_cname_rows
from .common import _stringify_value
from .dkim import _build_dkim_rows
from .dmarc import _build_dmarc_rows
from .generic import _build_generic_rows
from .mx import _build_mx_rows, _format_priority
from .spf import _build_spf_rows
from .srv import _build_srv_rows, _format_srv_entry
from .tlsa import _build_tlsa_rows, _format_tlsa_entry
from .txt import _build_txt_rows

_ROW_BUILDERS: Dict[str, callable] = {}
for record_type, builder_name in ROW_BUILDER_NAMES.items():
    builder = globals().get(builder_name) or _build_generic_rows
    _ROW_BUILDERS[record_type] = builder


def _build_result_rows(result: dict) -> List[dict]:
    """Build output rows for a serialized result.

    Args:
        result (dict): Serialized result.

    Returns:
        List[dict]: Row dicts for output.
    """
    record_type = result["record_type"]
    builder = _ROW_BUILDERS.get(record_type, _build_generic_rows)
    rows = builder(result)

    if not rows:
        rows = _build_generic_rows(result)

    return rows


__all__ = [
    "_build_address_rows",
    "_build_caa_rows",
    "_build_cname_rows",
    "_build_dkim_rows",
    "_build_dmarc_rows",
    "_build_generic_rows",
    "_build_mx_rows",
    "_build_result_rows",
    "_build_spf_rows",
    "_build_srv_rows",
    "_build_tlsa_rows",
    "_build_txt_rows",
    "_format_caa_entry",
    "_format_priority",
    "_format_srv_entry",
    "_format_tlsa_entry",
    "_stringify_value",
]
