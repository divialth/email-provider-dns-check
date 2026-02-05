"""SRV row builders."""

from __future__ import annotations

from typing import Iterable, List

from ...status import Status


def _format_srv_entry(entry: Iterable[object]) -> str:
    """Format an SRV entry tuple.

    Args:
        entry (Iterable[object]): SRV entry (priority, weight, port, target).

    Returns:
        str: Formatted SRV entry.
    """
    priority, weight, port, target = entry
    return f"priority {priority} weight {weight} port {port} target {target}"


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

    if not found and result["status"] == Status.PASS.value and expected:
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
                status = Status.PASS.value if found_value != "(missing)" else result["status"]
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
