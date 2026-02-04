"""DKIM row builders."""

from __future__ import annotations

from typing import List


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
