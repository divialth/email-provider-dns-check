"""DMARC row builders."""

from __future__ import annotations

from typing import List

from .common import _stringify_value


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
