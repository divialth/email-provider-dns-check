"""Output helpers for presenting DNS check results."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from jinja2 import Environment

from .checker import RecordCheck
from .provider_config import TEMPLATE_DIR_NAME, external_config_dirs

_ENV = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
_HUMAN_TABLE_HEADERS = ["Status", "Message", "Expected", "Found"]
_TEXT_TABLE_HEADERS = ["Status", "Item", "Expected", "Found"]


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
        payload = {
            "record_type": result.record_type,
            "status": result.status,
            "message": result.message,
            "details": details,
            "optional": result.optional,
            "selectors": selectors,
            "selector_rows": selector_rows,
        }
        payload["rows"] = _build_result_rows(payload)
        payload["table_rows"] = _build_row_cells(payload["rows"])
        serialized.append(payload)
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
    for result in results:
        table_rows = result.get("table_rows")
        if table_rows is None:
            rows.extend(_build_row_cells(_build_result_rows(result)))
        else:
            rows.extend(table_rows)
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


def _format_text_row(row: List[str], widths: List[int], indent: str = "  ") -> str:
    """Format a text row with padded columns.

    Args:
        row (List[str]): Row values.
        widths (List[int]): Column widths.
        indent (str): Prefix for the row.

    Returns:
        str: Formatted text row.
    """
    padded = [f"{cell:<{widths[i]}}" for i, cell in enumerate(row)]
    return f"{indent}{'  '.join(padded).rstrip()}"


def _build_text_widths(headers: List[str], rows: List[List[str]]) -> List[int]:
    """Compute column widths for aligned text output.

    Args:
        headers (List[str]): Column headers.
        rows (List[List[str]]): Row values.

    Returns:
        List[int]: Widths for each column.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def _stringify_value(value: object) -> str:
    """Serialize a value for display.

    Args:
        value (object): Value to serialize.

    Returns:
        str: Human-readable value.
    """
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(str(entry) for entry in value)
    if isinstance(value, tuple):
        return ", ".join(str(entry) for entry in value)
    return str(value)


def _format_priority(value: object) -> str:
    """Format MX priority data.

    Args:
        value (object): Priority value or list.

    Returns:
        str: Formatted priority string.
    """
    if value is None:
        return "-"
    if isinstance(value, list):
        if not value:
            return "-"
        label = "priority" if len(value) == 1 else "priorities"
        return f"{label} {', '.join(str(entry) for entry in value)}"
    return f"priority {value}"


def _format_srv_entry(entry: Iterable[object]) -> str:
    """Format an SRV entry tuple.

    Args:
        entry (Iterable[object]): SRV entry (priority, weight, port, target).

    Returns:
        str: Formatted SRV entry.
    """
    priority, weight, port, target = entry
    return f"priority {priority} weight {weight} port {port} target {target}"


def _build_dkim_rows(result: dict) -> List[dict]:
    """Build expected/found rows for DKIM results.

    Args:
        result (dict): Serialized DKIM result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    missing = set(details.get("missing", []))
    mismatched = details.get("mismatched", {})
    expected_targets = details.get("expected_targets", {})
    rows: List[dict] = []
    for selector in result.get("selector_rows", []):
        name = selector["name"]
        expected = selector.get("value")
        if expected is None:
            expected = expected_targets.get(name)
        if expected is None:
            expected = "present"
        found = expected
        if name in missing:
            found = "(missing)"
        elif name in mismatched:
            found = mismatched[name]
        rows.append(
            {
                "status": selector["status"],
                "message": f"DKIM selector {name}",
                "item": name,
                "expected": str(expected),
                "found": str(found),
            }
        )
    return rows


def _build_mx_rows(result: dict) -> List[dict]:
    """Build expected/found rows for MX results.

    Args:
        result (dict): Serialized MX result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = list(details.get("expected", []))
    found = list(details.get("found", []))
    missing = set(details.get("missing", []))
    extra = set(details.get("extra", []))
    mismatched = details.get("mismatched", {})

    if not expected:
        if missing:
            expected = sorted(set(found) | missing)
        elif extra:
            expected = sorted(set(found) - extra)
        else:
            expected = list(found)

    if expected and not found and not missing:
        missing = set(expected)

    rows: List[dict] = []
    for host in expected:
        status = "PASS"
        expected_value = "present"
        found_value = "present"
        if host in mismatched:
            status = "FAIL" if result["status"] == "FAIL" else "WARN"
            expected_value = _format_priority(mismatched[host].get("expected"))
            found_value = _format_priority(mismatched[host].get("found"))
        elif host in missing:
            status = "FAIL" if result["status"] == "FAIL" else "WARN"
            expected_value = "present"
            found_value = "(missing)"
        rows.append(
            {
                "status": status,
                "message": f"MX host {host}",
                "item": host,
                "expected": expected_value,
                "found": found_value,
            }
        )

    for host in sorted(extra):
        rows.append(
            {
                "status": result["status"],
                "message": f"MX extra host {host}",
                "item": host,
                "expected": "(none)",
                "found": "present",
            }
        )

    return rows


def _build_spf_rows(result: dict) -> List[dict]:
    """Build expected/found rows for SPF results.

    Args:
        result (dict): Serialized SPF result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected")
    found = details.get("found")
    record = details.get("record")
    extras = details.get("extras")
    rows: List[dict] = []

    if record is not None or expected is not None or found is not None:
        expected_value = expected
        if expected_value is None:
            if record is not None:
                expected_value = record
            elif isinstance(found, list) and len(found) > 1:
                expected_value = "single SPF record"
            else:
                expected_value = "-"
        found_value = record if record is not None else _stringify_value(found)
        if record is None and found is None:
            found_value = "(missing)"
        rows.append(
            {
                "status": result["status"],
                "message": "SPF record",
                "item": "record",
                "expected": str(expected_value),
                "found": str(found_value),
            }
        )

    if extras:
        rows.append(
            {
                "status": result["status"],
                "message": "SPF extra mechanisms",
                "item": "extra mechanisms",
                "expected": "(none)",
                "found": _stringify_value(extras),
            }
        )

    return rows


def _build_cname_rows(result: dict) -> List[dict]:
    """Build expected/found rows for CNAME results.

    Args:
        result (dict): Serialized CNAME result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected") or details.get("records") or {}
    found = details.get("found", {})
    missing = set(details.get("missing", []))
    mismatched = details.get("mismatched", {})
    rows: List[dict] = []

    for name in sorted(expected.keys()):
        expected_target = expected[name]
        status = "PASS"
        if name in mismatched:
            status = result["status"]
            found_target = mismatched[name]
        elif name in missing:
            status = result["status"]
            found_target = "(missing)"
        else:
            found_target = found.get(name, expected_target)
        rows.append(
            {
                "status": status,
                "message": f"CNAME {name}",
                "item": name,
                "expected": str(expected_target),
                "found": str(found_target),
            }
        )

    return rows


def _build_srv_rows(result: dict) -> List[dict]:
    """Build expected/found rows for SRV results.

    Args:
        result (dict): Serialized SRV result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected") or details.get("records") or {}
    found = details.get("found", {})
    missing = details.get("missing", {})
    mismatched = details.get("mismatched", {})
    extra = details.get("extra", {})
    rows: List[dict] = []

    if not found and result["status"] == "PASS" and expected:
        found = expected

    for name in sorted(expected.keys()):
        expected_entries = expected[name] or []
        missing_entries = {tuple(entry) for entry in missing.get(name, [])}
        mismatched_entries = {
            tuple(entry["expected"]): tuple(entry["found"]) for entry in mismatched.get(name, [])
        }
        found_entries = {tuple(entry) for entry in found.get(name, [])}
        for entry in expected_entries:
            entry_tuple = tuple(entry)
            expected_value = _format_srv_entry(entry_tuple)
            if entry_tuple in missing_entries:
                status = result["status"]
                found_value = "(missing)"
            elif entry_tuple in mismatched_entries:
                status = result["status"]
                found_value = _format_srv_entry(mismatched_entries[entry_tuple])
            else:
                found_value = expected_value if entry_tuple in found_entries else "(missing)"
                status = "PASS" if found_value != "(missing)" else result["status"]
            rows.append(
                {
                    "status": status,
                    "message": f"SRV {name}",
                    "item": name,
                    "expected": expected_value,
                    "found": found_value,
                }
            )

    for name in sorted(extra.keys()):
        for entry in extra[name]:
            entry_tuple = tuple(entry)
            rows.append(
                {
                    "status": result["status"],
                    "message": f"SRV {name} extra",
                    "item": name,
                    "expected": "(none)",
                    "found": _format_srv_entry(entry_tuple),
                }
            )

    return rows


def _format_caa_entry(entry: Dict[str, object]) -> str:
    """Format a CAA entry dict.

    Args:
        entry (Dict[str, object]): CAA entry mapping.

    Returns:
        str: Formatted CAA entry.
    """
    flags = entry.get("flags")
    tag = entry.get("tag")
    value = entry.get("value")
    return f"flags {flags} tag {tag} value {value}"


def _build_caa_rows(result: dict) -> List[dict]:
    """Build expected/found rows for CAA results.

    Args:
        result (dict): Serialized CAA result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected") or details.get("records") or {}
    found = details.get("found", {})
    missing = details.get("missing", {})
    extra = details.get("extra", {})
    rows: List[dict] = []

    if not found and result["status"] == "PASS" and expected:
        found = expected

    for name in sorted(expected.keys()):
        expected_entries = expected[name] or []
        missing_entries = missing.get(name, [])
        for entry in expected_entries:
            status = "PASS"
            found_value = _format_caa_entry(entry)
            if entry in missing_entries:
                status = result["status"]
                found_value = "(missing)"
            rows.append(
                {
                    "status": status,
                    "message": f"CAA {name}",
                    "item": name,
                    "expected": _format_caa_entry(entry),
                    "found": found_value,
                }
            )

    for name in sorted(extra.keys()):
        for entry in extra[name]:
            rows.append(
                {
                    "status": result["status"],
                    "message": f"CAA {name} extra",
                    "item": name,
                    "expected": "(none)",
                    "found": _format_caa_entry(entry),
                }
            )

    return rows


def _build_txt_rows(result: dict) -> List[dict]:
    """Build expected/found rows for TXT results.

    Args:
        result (dict): Serialized TXT result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    rows: List[dict] = []
    missing = details.get("missing", {})
    missing_names = details.get("missing_names", [])
    required = details.get("required")
    verification_required = details.get("verification_required")

    if isinstance(missing, dict):
        for name in sorted(missing.keys()):
            for value in missing[name]:
                rows.append(
                    {
                        "status": result["status"],
                        "message": f"TXT {name}",
                        "item": name,
                        "expected": str(value),
                        "found": "(missing)",
                    }
                )

    if missing_names:
        for name in sorted(missing_names):
            rows.append(
                {
                    "status": result["status"],
                    "message": f"TXT {name}",
                    "item": name,
                    "expected": "record present",
                    "found": "(missing)",
                }
            )

    if verification_required:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT verification required",
                "item": "verification",
                "expected": str(verification_required),
                "found": "(missing)",
            }
        )

    if isinstance(required, dict):
        for name in sorted(required.keys()):
            values = required[name]
            if isinstance(values, list):
                for value in values:
                    rows.append(
                        {
                            "status": result["status"],
                            "message": f"TXT {name}",
                            "item": name,
                            "expected": str(value),
                            "found": str(value) if result["status"] == "PASS" else "(missing)",
                        }
                    )
            else:
                rows.append(
                    {
                        "status": result["status"],
                        "message": f"TXT {name}",
                        "item": name,
                        "expected": str(values),
                        "found": str(values) if result["status"] == "PASS" else "(missing)",
                    }
                )
    elif required:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT requirement",
                "item": "required",
                "expected": str(required),
                "found": str(required) if result["status"] == "PASS" else "(missing)",
            }
        )

    if not rows:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT records",
                "item": "TXT",
                "expected": "(none)",
                "found": "(none)",
            }
        )

    return rows


def _build_dmarc_rows(result: dict) -> List[dict]:
    """Build expected/found rows for DMARC results.

    Args:
        result (dict): Serialized DMARC result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected")
    found = details.get("found")
    record = details.get("record")
    rows: List[dict] = []

    if record is not None or expected is not None or found is not None:
        expected_value = expected if expected is not None else record
        found_value = record if record is not None else _stringify_value(found)
        if record is None and found is None:
            found_value = "(missing)"
        rows.append(
            {
                "status": result["status"],
                "message": "DMARC record",
                "item": "record",
                "expected": str(expected_value) if expected_value is not None else "-",
                "found": str(found_value),
            }
        )

    return rows


def _build_generic_rows(result: dict) -> List[dict]:
    """Build fallback rows for unknown result types.

    Args:
        result (dict): Serialized result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    rows: List[dict] = []
    if "error" in details:
        rows.append(
            {
                "status": result["status"],
                "message": "Error",
                "item": "error",
                "expected": "-",
                "found": str(details["error"]),
            }
        )
        return rows

    for key, value in details.items():
        rows.append(
            {
                "status": result["status"],
                "message": str(key),
                "item": str(key),
                "expected": str(value),
                "found": "-",
            }
        )

    if not rows:
        rows.append(
            {
                "status": result["status"],
                "message": "No details",
                "item": "-",
                "expected": "-",
                "found": "-",
            }
        )

    return rows


def _build_result_rows(result: dict) -> List[dict]:
    """Build output rows for a serialized result.

    Args:
        result (dict): Serialized result.

    Returns:
        List[dict]: Row dicts for output.
    """
    record_type = result["record_type"]
    if record_type == "DKIM":
        rows = _build_dkim_rows(result)
    elif record_type == "MX":
        rows = _build_mx_rows(result)
    elif record_type == "SPF":
        rows = _build_spf_rows(result)
    elif record_type == "CNAME":
        rows = _build_cname_rows(result)
    elif record_type == "SRV":
        rows = _build_srv_rows(result)
    elif record_type == "CAA":
        rows = _build_caa_rows(result)
    elif record_type == "TXT":
        rows = _build_txt_rows(result)
    elif record_type == "DMARC":
        rows = _build_dmarc_rows(result)
    else:
        rows = _build_generic_rows(result)

    if not rows:
        rows = _build_generic_rows(result)

    return rows


def _build_row_cells(rows: List[dict]) -> List[List[str]]:
    """Convert row dicts into table cell lists.

    Args:
        rows (List[dict]): Row dicts.

    Returns:
        List[List[str]]: Row cells for tables.
    """
    return [[row["status"], row["message"], row["expected"], row["found"]] for row in rows]


def _build_text_cells(rows: List[dict]) -> List[List[str]]:
    """Convert row dicts into text table cells.

    Args:
        rows (List[dict]): Row dicts.

    Returns:
        List[List[str]]: Row cells for text output.
    """
    return [[row["status"], row["item"], row["expected"], row["found"]] for row in rows]


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
        "format_text_row": _format_text_row,
        "stringify_details": _stringify_details,
        "build_table_rows": _build_table_rows,
        "build_table_widths": _build_table_widths,
        "build_table_separator": _build_table_separator,
        "text_headers": _TEXT_TABLE_HEADERS,
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
    summary = summarize_status(results)
    header = f"{summary} - report for domain {domain} ({report_time}) / provider: {_provider_label(provider_name, provider_version)}"
    lines = [header, ""]
    for idx, result in enumerate(serialized):
        if idx:
            lines.append("")
        section_header = f"{result['record_type']}: {result['status']} - {result['message']}"
        lines.append(section_header)
        text_rows = _build_text_cells(result["rows"])
        result["text_rows"] = text_rows
        if text_rows:
            widths = _build_text_widths(_TEXT_TABLE_HEADERS, text_rows)
            result["text_widths"] = widths
            lines.append(_format_text_row(_TEXT_TABLE_HEADERS, widths))
            for row in text_rows:
                lines.append(_format_text_row(row, widths))
    context = _template_context(
        domain=domain,
        report_time=report_time,
        provider_name=provider_name,
        provider_version=provider_version,
        summary=summary,
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
