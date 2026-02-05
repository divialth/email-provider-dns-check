"""Output helpers for presenting DNS check results."""

from __future__ import annotations

import json
from typing import Callable, List, Optional

from ..checker import RecordCheck
from ..status import Status
from .serialize import _serialize_results
from .tables import (
    _build_table_rows,
    _build_table_separator,
    _build_table_widths,
    _build_text_cells,
    _build_text_widths,
    _format_row,
    _format_text_row,
)
from .templates import _provider_label, _render_template

_HUMAN_TABLE_HEADERS = ["Status", "Message", "Expected", "Found"]
_TEXT_TABLE_HEADERS = ["Status", "Item", "Expected", "Found"]


def _template_context(
    *,
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
    summary: str,
    results: List[dict],
    lines: List[str],
    colorize_status: Callable[[str], str] | None = None,
    table_headers: Optional[List[str]] = None,
) -> dict:
    """Build a template context for output rendering.

    Args:
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.
        summary (str): Summary status string.
        results (List[dict]): Serialized results.
        lines (List[str]): Pre-rendered text lines.
        colorize_status (Callable[[str], str] | None): Status colorizer callback.
        table_headers (Optional[List[str]]): Optional table headers.

    Returns:
        dict: Template context mapping.
    """
    provider_label = _provider_label(provider_name, provider_version)
    if colorize_status is None:
        colorize_status = lambda text: text
    context = {
        "domain": domain,
        "report_time": report_time,
        "provider_name": provider_name,
        "provider_version": provider_version,
        "provider_label": provider_label,
        "summary": summary,
        "results": results,
        "lines": lines,
        "format_row": _format_row,
        "format_text_row": _format_text_row,
        "stringify_details": _stringify_details,
        "build_table_rows": _build_table_rows,
        "build_table_widths": _build_table_widths,
        "build_table_separator": _build_table_separator,
        "text_headers": _TEXT_TABLE_HEADERS,
        "colorize_status": colorize_status,
    }
    if table_headers is not None:
        context["table_headers"] = table_headers
    return context


def build_json_payload(
    results: List[RecordCheck],
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
) -> dict:
    """Build a JSON-serializable payload for results.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        dict: JSON-serializable payload.
    """
    return {
        "domain": domain,
        "provider": provider_name,
        "provider_config_version": provider_version,
        "report_time_utc": report_time,
        "results": [
            {
                "record_type": result.record_type,
                "status": result.status,
                "message": result.message,
                "details": result.details,
                "optional": result.optional,
            }
            for result in results
        ],
    }


def to_json(
    results: List[RecordCheck],
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
) -> str:
    """Render results as formatted JSON.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        str: JSON string.
    """
    payload = build_json_payload(results, domain, report_time, provider_name, provider_version)
    return json.dumps(payload, indent=2)


def to_text(
    results: List[RecordCheck],
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
    *,
    colorize_status: Callable[[str], str] | None = None,
) -> str:
    """Render results as plain text output.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.
        colorize_status (Callable[[str], str] | None): Status colorizer callback.

    Returns:
        str: Rendered text output.
    """
    if colorize_status is None:
        colorize_status = lambda text: text
    serialized = _serialize_results(results)
    summary = summarize_status(results)
    header = (
        f"{colorize_status(summary)} - report for domain {domain} ({report_time}) / provider: "
        f"{_provider_label(provider_name, provider_version)}"
    )
    lines = [header, ""]
    for idx, result in enumerate(serialized):
        if idx:
            lines.append("")
        section_header = (
            f"{result['record_type']}: {colorize_status(result['status'])} - "
            f"{result['message']}"
        )
        lines.append(section_header)
        text_rows = _build_text_cells(result["rows"])
        result["text_rows"] = text_rows
        if text_rows:
            widths = _build_text_widths(_TEXT_TABLE_HEADERS, text_rows)
            result["text_widths"] = widths
            lines.append(
                _format_text_row(
                    _TEXT_TABLE_HEADERS,
                    widths,
                    colorize_status=colorize_status,
                )
            )
            for row in text_rows:
                lines.append(_format_text_row(row, widths, colorize_status=colorize_status))
    context = _template_context(
        domain=domain,
        report_time=report_time,
        provider_name=provider_name,
        provider_version=provider_version,
        summary=summary,
        results=serialized,
        lines=lines,
        colorize_status=colorize_status,
    )
    return _render_template("text.j2", context)


def _stringify_details(details: dict) -> str:
    """Serialize details for output.

    Args:
        details (dict): Details mapping.

    Returns:
        str: Compact JSON string or "-" when empty.
    """
    if not details:
        return "-"
    return json.dumps(details, separators=(",", ":"))


def to_human(
    results: List[RecordCheck],
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
    *,
    colorize_status: Callable[[str], str] | None = None,
) -> str:
    """Render results as a markdown table for human-friendly output.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.
        colorize_status (Callable[[str], str] | None): Status colorizer callback.

    Returns:
        str: Rendered markdown output.
    """
    serialized = _serialize_results(results)
    summary = summarize_status(results)
    for result in serialized:
        result["table_widths"] = _build_table_widths(_HUMAN_TABLE_HEADERS, result["table_rows"])
    context = _template_context(
        domain=domain,
        report_time=report_time,
        provider_name=provider_name,
        provider_version=provider_version,
        summary=summary,
        results=serialized,
        lines=[],
        table_headers=_HUMAN_TABLE_HEADERS,
        colorize_status=colorize_status,
    )
    return _render_template("human.j2", context)


def summarize_status(results: List[RecordCheck]) -> str:
    """Summarize results into a single status string.

    Args:
        results (List[RecordCheck]): DNS check results.

    Returns:
        str: Summary status (FAIL, WARN, UNKNOWN, or PASS).
    """
    fail = any(r.status == Status.FAIL.value for r in results)
    warn = any(r.status == Status.WARN.value for r in results)
    unknown = any(r.status == Status.UNKNOWN.value for r in results)
    if fail:
        return Status.FAIL.value
    if warn:
        return Status.WARN.value
    if unknown:
        return Status.UNKNOWN.value
    return Status.PASS.value
