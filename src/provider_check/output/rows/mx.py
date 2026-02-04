"""MX row builders."""

from __future__ import annotations

from typing import List


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
