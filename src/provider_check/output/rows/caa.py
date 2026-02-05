"""CAA row builders."""

from __future__ import annotations

from typing import Dict, List

from ...status import Status


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

    if not found and result["status"] == Status.PASS.value and expected:
        found = expected

    for name in sorted(expected.keys()):
        expected_entries = expected[name] or []
        missing_entries = missing.get(name, [])
        for entry in expected_entries:
            status = Status.PASS.value
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
