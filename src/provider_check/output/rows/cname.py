"""CNAME row builders."""

from __future__ import annotations

from typing import List


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
