"""Output helpers for presenting DNS check results."""

from __future__ import annotations

from .color import make_status_colorizer, resolve_color_enabled, strip_ansi
from .formatters import (
    _stringify_details,
    build_json_payload,
    summarize_status,
    to_human,
    to_json,
    to_text,
)
from .rows import (
    _build_address_rows,
    _build_caa_rows,
    _build_cname_rows,
    _build_dkim_rows,
    _build_dmarc_rows,
    _build_generic_rows,
    _build_mx_rows,
    _build_result_rows,
    _build_spf_rows,
    _build_srv_rows,
    _build_tlsa_rows,
    _build_txt_rows,
    _format_priority,
    _format_srv_entry,
    _format_tlsa_entry,
    _stringify_value,
)
from .serialize import _serialize_results
from .tables import _build_table_rows

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
    "_build_table_rows",
    "_build_txt_rows",
    "_format_priority",
    "_format_srv_entry",
    "_format_tlsa_entry",
    "_serialize_results",
    "_stringify_details",
    "_stringify_value",
    "build_json_payload",
    "make_status_colorizer",
    "resolve_color_enabled",
    "summarize_status",
    "strip_ansi",
    "to_human",
    "to_json",
    "to_text",
]
