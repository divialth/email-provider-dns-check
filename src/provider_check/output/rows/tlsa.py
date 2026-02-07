"""TLSA row builders."""

from __future__ import annotations

from typing import Dict, List

from ...status import Status


def _format_tlsa_entry(entry: tuple[int, int, int, str]) -> str:
    """Format a TLSA entry tuple.

    Args:
        entry (tuple[int, int, int, str]): TLSA entry tuple.

    Returns:
        str: Formatted TLSA entry.
    """
    usage, selector, matching_type, certificate_association = entry
    return (
        f"usage {usage} selector {selector} matching_type {matching_type} "
        f"certificate_association {certificate_association}"
    )


def _build_tlsa_rows(result: dict) -> List[dict]:
    """Build expected/found rows for TLSA results.

    Args:
        result (dict): Serialized TLSA result.

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

    for name in sorted(expected.keys()):
        expected_entries = expected[name] or []
        missing_entries = {tuple(entry) for entry in missing.get(name, [])}
        found_entries = {tuple(entry) for entry in found.get(name, [])}
        for entry in expected_entries:
            entry_tuple = tuple(entry)
            expected_value = _format_tlsa_entry(entry_tuple)
            found_value = expected_value if entry_tuple in found_entries else "(missing)"
            row_status = Status.PASS.value
            if entry_tuple in missing_entries:
                row_status = result["status"]
                found_value = "(missing)"
            elif found_value == "(missing)":
                row_status = result["status"]
            rows.append(
                {
                    "status": row_status,
                    "message": f"TLSA {name}",
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
                    "message": f"TLSA {name} extra",
                    "item": name,
                    "expected": "(none)",
                    "found": _format_tlsa_entry(entry_tuple),
                }
            )

    return rows
