"""SPF row builders."""

from __future__ import annotations

from typing import List

from .common import _stringify_value


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
