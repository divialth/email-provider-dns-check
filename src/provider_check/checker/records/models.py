"""Record check models."""

from __future__ import annotations

import dataclasses
from typing import Dict, Optional

from ...status import Status, coerce_status


@dataclasses.dataclass
class RecordCheck:
    """Represent the outcome of a DNS record validation.

    Attributes:
        record_type (str): DNS record type being validated (e.g., MX, SPF, DKIM).
        status (Status): Result status.
        message (str): Human-readable summary of the outcome.
        details (Dict[str, object]): Structured details for debugging or output.
        optional (bool): Whether the check is for optional records.
    """

    record_type: str
    status: Status
    message: str
    details: Dict[str, object]
    optional: bool = False

    def __post_init__(self) -> None:
        """Normalize status values to Status."""
        if not isinstance(self.status, Status):
            self.status = coerce_status(self.status)

    @classmethod
    def with_status(
        cls,
        record_type: str,
        status: Status,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
    ) -> "RecordCheck":
        """Build a RecordCheck for a specific status.

        Args:
            record_type (str): DNS record type being validated.
            status (Status): Status to assign.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.

        Returns:
            RecordCheck: Record check result.
        """
        return cls(record_type, status, message, details or {}, optional=optional)

    @classmethod
    def pass_(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
    ) -> "RecordCheck":
        """Build a passing RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.

        Returns:
            RecordCheck: Record check result with PASS status.
        """
        return cls.with_status(
            record_type,
            Status.PASS,
            message,
            details,
            optional=optional,
        )

    @classmethod
    def warn(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
    ) -> "RecordCheck":
        """Build a warning RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.

        Returns:
            RecordCheck: Record check result with WARN status.
        """
        return cls.with_status(
            record_type,
            Status.WARN,
            message,
            details,
            optional=optional,
        )

    @classmethod
    def fail(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
    ) -> "RecordCheck":
        """Build a failed RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.

        Returns:
            RecordCheck: Record check result with FAIL status.
        """
        return cls.with_status(
            record_type,
            Status.FAIL,
            message,
            details,
            optional=optional,
        )

    @classmethod
    def unknown(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
    ) -> "RecordCheck":
        """Build an unknown RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.

        Returns:
            RecordCheck: Record check result with UNKNOWN status.
        """
        return cls.with_status(
            record_type,
            Status.UNKNOWN,
            message,
            details,
            optional=optional,
        )
