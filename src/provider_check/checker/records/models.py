"""Record check models."""

from __future__ import annotations

import dataclasses
from typing import Dict


@dataclasses.dataclass
class RecordCheck:
    """Represent the outcome of a DNS record validation.

    Attributes:
        record_type (str): DNS record type being validated (e.g., MX, SPF, DKIM).
        status (str): Result status (see provider_check.status.Status).
        message (str): Human-readable summary of the outcome.
        details (Dict[str, object]): Structured details for debugging or output.
        optional (bool): Whether the check is for optional records.
    """

    record_type: str
    status: str  # Status enum value
    message: str
    details: Dict[str, object]
    optional: bool = False
