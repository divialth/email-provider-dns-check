"""Row builders for output rendering."""

from __future__ import annotations

from typing import Dict, Iterable, List


def _stringify_value(value: object) -> str:
    """Serialize a value for display.

    Args:
        value (object): Value to serialize.

    Returns:
        str: Human-readable value.
    """
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(str(entry) for entry in value)
    if isinstance(value, tuple):
        return ", ".join(str(entry) for entry in value)
    return str(value)


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


def _format_srv_entry(entry: Iterable[object]) -> str:
    """Format an SRV entry tuple.

    Args:
        entry (Iterable[object]): SRV entry (priority, weight, port, target).

    Returns:
        str: Formatted SRV entry.
    """
    priority, weight, port, target = entry
    return f"priority {priority} weight {weight} port {port} target {target}"


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


def _build_address_rows(result: dict) -> List[dict]:
    """Build expected/found rows for A/AAAA results.

    Args:
        result (dict): Serialized A/AAAA result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    expected = details.get("expected") or details.get("records") or {}
    found = details.get("found", {})
    missing = details.get("missing", {})
    extra = details.get("extra", {})
    rows: List[dict] = []

    if not found and result["status"] == "PASS" and expected:
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
                status = "PASS"
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

    if not found and result["status"] == "PASS" and expected:
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
                status = "PASS" if found_value != "(missing)" else result["status"]
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

    if not found and result["status"] == "PASS" and expected:
        found = expected

    for name in sorted(expected.keys()):
        expected_entries = expected[name] or []
        missing_entries = missing.get(name, [])
        for entry in expected_entries:
            status = "PASS"
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


def _build_txt_rows(result: dict) -> List[dict]:
    """Build expected/found rows for TXT results.

    Args:
        result (dict): Serialized TXT result.

    Returns:
        List[dict]: Row dicts for output.
    """
    details = result["details"]
    rows: List[dict] = []
    missing = details.get("missing", {})
    missing_names = details.get("missing_names", [])
    required = details.get("required")
    verification_required = details.get("verification_required")

    if isinstance(missing, dict):
        for name in sorted(missing.keys()):
            for value in missing[name]:
                rows.append(
                    {
                        "status": result["status"],
                        "message": f"TXT {name}",
                        "item": name,
                        "expected": str(value),
                        "found": "(missing)",
                    }
                )

    if missing_names:
        for name in sorted(missing_names):
            rows.append(
                {
                    "status": result["status"],
                    "message": f"TXT {name}",
                    "item": name,
                    "expected": "record present",
                    "found": "(missing)",
                }
            )

    if verification_required:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT verification required",
                "item": "verification",
                "expected": str(verification_required),
                "found": "(missing)",
            }
        )

    if isinstance(required, dict):
        for name in sorted(required.keys()):
            values = required[name]
            if isinstance(values, list):
                for value in values:
                    rows.append(
                        {
                            "status": result["status"],
                            "message": f"TXT {name}",
                            "item": name,
                            "expected": str(value),
                            "found": str(value) if result["status"] == "PASS" else "(missing)",
                        }
                    )
            else:
                rows.append(
                    {
                        "status": result["status"],
                        "message": f"TXT {name}",
                        "item": name,
                        "expected": str(values),
                        "found": str(values) if result["status"] == "PASS" else "(missing)",
                    }
                )
    elif required:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT requirement",
                "item": "required",
                "expected": str(required),
                "found": str(required) if result["status"] == "PASS" else "(missing)",
            }
        )

    if not rows:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT records",
                "item": "TXT",
                "expected": "(none)",
                "found": "(none)",
            }
        )

    return rows


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


def _build_result_rows(result: dict) -> List[dict]:
    """Build output rows for a serialized result.

    Args:
        result (dict): Serialized result.

    Returns:
        List[dict]: Row dicts for output.
    """
    record_type = result["record_type"]
    if record_type == "DKIM":
        rows = _build_dkim_rows(result)
    elif record_type == "MX":
        rows = _build_mx_rows(result)
    elif record_type == "SPF":
        rows = _build_spf_rows(result)
    elif record_type == "CNAME":
        rows = _build_cname_rows(result)
    elif record_type in {"A", "AAAA"}:
        rows = _build_address_rows(result)
    elif record_type == "SRV":
        rows = _build_srv_rows(result)
    elif record_type == "CAA":
        rows = _build_caa_rows(result)
    elif record_type == "TXT":
        rows = _build_txt_rows(result)
    elif record_type == "DMARC":
        rows = _build_dmarc_rows(result)
    else:
        rows = _build_generic_rows(result)

    if not rows:
        rows = _build_generic_rows(result)

    return rows
