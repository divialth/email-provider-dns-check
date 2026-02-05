"""Serialization helpers for output."""

from __future__ import annotations

from typing import Dict, List

from ..checker import RecordCheck
from ..status import Status
from .rows import _build_result_rows
from .tables import _build_row_cells


def _serialize_results(results: List[RecordCheck]) -> List[dict]:
    """Serialize RecordCheck results for output templates.

    Args:
        results (List[RecordCheck]): Raw check results.

    Returns:
        List[dict]: Serialized results with selector rows for DKIM.
    """
    serialized: List[dict] = []
    for result in results:
        details = dict(result.details)
        selectors: dict = {}
        selector_rows: List[dict] = []
        if result.record_type == "DKIM":
            if "selectors" in details:
                selectors = details.pop("selectors", {})
            expected_selectors = details.get("expected_selectors")
            missing = set(details.get("missing", []))
            mismatched = details.get("mismatched", {})
            expected_targets = details.get("expected_targets", {})
            if expected_selectors:
                for selector in expected_selectors:
                    row_status = Status.PASS.value
                    row_message = "DKIM selector valid"
                    row_details: Dict[str, object] = {}
                    if selector in expected_targets:
                        row_details["expected"] = expected_targets[selector]
                    if selector in missing:
                        row_status = (
                            Status.FAIL.value
                            if result.status == Status.FAIL.value
                            else Status.WARN.value
                        )
                        row_message = "DKIM selector missing"
                    elif selector in mismatched:
                        row_status = (
                            Status.FAIL.value
                            if result.status == Status.FAIL.value
                            else Status.WARN.value
                        )
                        row_message = "DKIM selector mismatched"
                        row_details["found"] = mismatched[selector]
                    selector_rows.append(
                        {
                            "name": selector,
                            "status": row_status,
                            "message": row_message,
                            "value": expected_targets.get(selector),
                            "details": row_details,
                        }
                    )
            elif selectors:
                for selector, target in selectors.items():
                    selector_rows.append(
                        {
                            "name": selector,
                            "status": Status.PASS.value,
                            "message": "DKIM selector valid",
                            "value": target,
                            "details": {"selector": {selector: target}},
                        }
                    )
        payload = {
            "record_type": result.record_type,
            "status": result.status,
            "message": result.message,
            "details": details,
            "optional": result.optional,
            "selectors": selectors,
            "selector_rows": selector_rows,
        }
        payload["rows"] = _build_result_rows(payload)
        payload["table_rows"] = _build_row_cells(payload["rows"])
        serialized.append(payload)
    return serialized
