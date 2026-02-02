"""Output helpers for presenting DNS check results."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import List, Optional

from jinja2 import Environment

from .checker import RecordCheck
from .provider_config import TEMPLATE_DIR_NAME, external_config_dirs

_ENV = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
_HUMAN_TABLE_HEADERS = ["Record type", "Status", "Message", "Details"]


def _provider_label(provider_name: str, provider_version: str) -> str:
    """Build a display label for a provider.

    Args:
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        str: Label including provider name and version.
    """
    return f"{provider_name} (v{provider_version})"


def _find_template_path(template_name: str) -> Optional[Path]:
    """Find an external template override path.

    Args:
        template_name (str): Template filename to locate.

    Returns:
        Optional[Path]: Path to override template if found.
    """
    for base_dir in external_config_dirs():
        candidate = base_dir / TEMPLATE_DIR_NAME / template_name
        if candidate.is_file():
            return candidate
    return None


def _render_template(template_name: str, context: dict) -> str:
    """Render a template with the provided context.

    Args:
        template_name (str): Template filename to render.
        context (dict): Render context.

    Returns:
        str: Rendered template output.
    """
    override_path = _find_template_path(template_name)
    if override_path:
        source = override_path.read_text(encoding="utf-8")
    else:
        source = (
            resources.files("provider_check.templates")
            .joinpath(template_name)
            .read_text(encoding="utf-8")
        )
    return _ENV.from_string(source).render(**context)


def _serialize_results(results: List[RecordCheck]) -> List[dict]:
    """Serialize RecordCheck results for output templates.

    Args:
        results (List[RecordCheck]): Raw check results.

    Returns:
        List[dict]: Serialized results with selector rows for DKIM.
    """
    serialized: List[dict] = []
    for result in results:
        details = dict(result.details)
        selectors: dict = {}
        selector_rows: List[dict] = []
        if result.record_type == "DKIM":
            if "selectors" in details:
                selectors = details.pop("selectors", {})
            expected_selectors = details.get("expected_selectors")
            missing = set(details.get("missing", []))
            mismatched = details.get("mismatched", {})
            expected_targets = details.get("expected_targets", {})
            if expected_selectors:
                for selector in expected_selectors:
                    row_status = "PASS"
                    row_message = "DKIM selector valid"
                    row_details: Dict[str, object] = {}
                    if selector in expected_targets:
                        row_details["expected"] = expected_targets[selector]
                    if selector in missing:
                        row_status = "FAIL" if result.status == "FAIL" else "WARN"
                        row_message = "DKIM selector missing"
                    elif selector in mismatched:
                        row_status = "FAIL" if result.status == "FAIL" else "WARN"
                        row_message = "DKIM selector mismatched"
                        row_details["found"] = mismatched[selector]
                    selector_rows.append(
                        {
                            "name": selector,
                            "status": row_status,
                            "message": row_message,
                            "value": expected_targets.get(selector),
                            "details": row_details,
                        }
                    )
            elif selectors:
                for selector, target in selectors.items():
                    selector_rows.append(
                        {
                            "name": selector,
                            "status": "PASS",
                            "message": "DKIM selector valid",
                            "value": target,
                            "details": {"selector": {selector: target}},
                        }
                    )
        serialized.append(
            {
                "record_type": result.record_type,
                "status": result.status,
                "message": result.message,
                "details": details,
                "selectors": selectors,
                "selector_rows": selector_rows,
            }
        )
    return serialized


def _format_row(row: List[str], widths: List[int]) -> str:
    """Format a markdown table row with padded cells.

    Args:
        row (List[str]): Row values.
        widths (List[int]): Column widths.

    Returns:
        str: Formatted markdown table row.
    """
    padded = [f"{cell:<{widths[i]}}" for i, cell in enumerate(row)]
    return "| " + " | ".join(padded) + " |"


def _build_table_rows(results: List[dict]) -> List[List[str]]:
    """Build markdown table rows for serialized results.

    Args:
        results (List[dict]): Serialized results.

    Returns:
        List[List[str]]: Table rows.
    """
    rows: List[List[str]] = []
    last_record_type: str | None = None
    for result in results:
        if last_record_type and result["record_type"] != last_record_type:
            rows.append(["", "", "—", ""])
        details_value = (
            ""
            if result["record_type"] == "DKIM" and result.get("selector_rows")
            else _stringify_details(result["details"]) if result["details"] else ""
        )
        rows.append(
            [
                result["record_type"],
                result["status"],
                result["message"],
                details_value,
            ]
        )
        if result["record_type"] == "DKIM" and result.get("selector_rows"):
            for selector in result["selector_rows"]:
                rows.append(
                    [
                        result["record_type"],
                        selector["status"],
                        selector["message"],
                        _stringify_details(selector.get("details", {})),
                    ]
                )
        last_record_type = result["record_type"]
    return rows


def _build_table_widths(headers: List[str], rows: List[List[str]]) -> List[int]:
    """Compute column widths for a markdown table.

    Args:
        headers (List[str]): Table headers.
        rows (List[List[str]]): Table rows.

    Returns:
        List[int]: Widths for each column.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def _build_table_separator(widths: List[int]) -> str:
    """Build a markdown table separator row.

    Args:
        widths (List[int]): Column widths.

    Returns:
        str: Markdown separator row.
    """
    return "| " + " | ".join("-" * max(3, width) for width in widths) + " |"


def _template_context(
    *,
    domain: str,
    report_time: str,
    provider_name: str,
    provider_version: str,
    summary: str,
    results: List[dict],
    lines: List[str],
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
        table_headers (Optional[List[str]]): Optional table headers.

    Returns:
        dict: Template context mapping.
    """
    provider_label = _provider_label(provider_name, provider_version)
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
        "stringify_details": _stringify_details,
        "build_table_rows": _build_table_rows,
        "build_table_widths": _build_table_widths,
        "build_table_separator": _build_table_separator,
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
) -> str:
    """Render results as plain text output.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        str: Rendered text output.
    """
    serialized = _serialize_results(results)
    header = f"report for domain {domain} ({report_time})"
    lines = [header, f"provider: {_provider_label(provider_name, provider_version)}", "----"]
    for idx, result in enumerate(serialized):
        if idx:
            lines.append("")
        header = f"{result['record_type']}: {result['status']} - {result['message']}"
        lines.append(header)
        if result["record_type"] == "DKIM" and result["selectors"]:
            selectors = result["selectors"]
            for selector, target in selectors.items():
                lines.append(f"  {selector} -> {target}")
            remaining_details = result["details"]
        else:
            remaining_details = result["details"]

        for key, value in remaining_details.items():
            lines.append(f"  {key}: {value}")
    context = _template_context(
        domain=domain,
        report_time=report_time,
        provider_name=provider_name,
        provider_version=provider_version,
        summary=summarize_status(results),
        results=serialized,
        lines=lines,
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
) -> str:
    """Render results as a markdown table for human-friendly output.

    Args:
        results (List[RecordCheck]): DNS check results.
        domain (str): Domain being reported.
        report_time (str): UTC report timestamp string.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        str: Rendered markdown output.
    """
    serialized = _serialize_results(results)
    headline = f"report for domain {domain} ({report_time})"
    provider_line = f"provider: {_provider_label(provider_name, provider_version)}"
    context = _template_context(
        domain=domain,
        report_time=report_time,
        provider_name=provider_name,
        provider_version=provider_version,
        summary=summarize_status(results),
        results=serialized,
        lines=[headline, provider_line, "----"],
        table_headers=_HUMAN_TABLE_HEADERS,
    )
    return _render_template("human.j2", context)


def summarize_status(results: List[RecordCheck]) -> str:
    """Summarize results into a single status string.

    Args:
        results (List[RecordCheck]): DNS check results.

    Returns:
        str: Summary status (FAIL, WARN, UNKNOWN, or PASS).
    """
    fail = any(r.status == "FAIL" for r in results)
    warn = any(r.status == "WARN" for r in results)
    unknown = any(r.status == "UNKNOWN" for r in results)
    if fail:
        return "FAIL"
    if warn:
        return "WARN"
    if unknown:
        return "UNKNOWN"
    return "PASS"
