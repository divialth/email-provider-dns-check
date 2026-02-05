"""TXT row builders."""

from __future__ import annotations

from typing import List

from ...status import Status


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
                            "found": (
                                str(value) if result["status"] == Status.PASS.value else "(missing)"
                            ),
                        }
                    )
            else:
                rows.append(
                    {
                        "status": result["status"],
                        "message": f"TXT {name}",
                        "item": name,
                        "expected": str(values),
                        "found": (
                            str(values) if result["status"] == Status.PASS.value else "(missing)"
                        ),
                    }
                )
    elif required:
        rows.append(
            {
                "status": result["status"],
                "message": "TXT requirement",
                "item": "required",
                "expected": str(required),
                "found": str(required) if result["status"] == Status.PASS.value else "(missing)",
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
