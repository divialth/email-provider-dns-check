"""Generic row builders."""

from __future__ import annotations

from typing import List


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
