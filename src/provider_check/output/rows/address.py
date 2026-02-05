"""Address row builders."""

from __future__ import annotations

from typing import List

from ...status import Status


def _build_address_rows(result: dict) -> List[dict]:
    """Build expected/found rows for A/AAAA results.

    Args:
        result (dict): Serialized A/AAAA result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected") or {}
    found = details.get("found", {})
    missing = details.get("missing", {})
    extra = details.get("extra", {})
    rows: List[dict] = []

    if not found and result["status"] == Status.PASS.value and expected:
        found = expected

    record_label = result["record_type"]
    for name in sorted(expected.keys()):
        expected_values = expected[name] or []
        missing_values = set(missing.get(name, []))
        found_values = set(found.get(name, []))
        for value in expected_values:
            if value in missing_values:
                status = result["status"]
                found_value = "(missing)"
            elif value in found_values:
                status = Status.PASS.value
                found_value = value
            else:
                status = result["status"]
                found_value = "(missing)"
            rows.append(
                {
                    "status": status,
                    "message": f"{record_label} {name}",
                    "item": name,
                    "expected": str(value),
                    "found": str(found_value),
                }
            )

    for name in sorted(extra.keys()):
        for value in extra[name]:
            rows.append(
                {
                    "status": result["status"],
                    "message": f"{record_label} {name} extra",
                    "item": name,
                    "expected": "(none)",
                    "found": str(value),
                }
            )

    return rows
