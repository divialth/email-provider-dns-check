"""Record check models."""

from __future__ import annotations

import dataclasses
from typing import Dict, Optional

from ...status import Status, coerce_status

_RECORD_SCOPES = frozenset({"required", "optional", "deprecated", "forbidden"})


@dataclasses.dataclass
class RecordCheck:
    """Represent the outcome of a DNS record validation.

    Attributes:
        record_type (str): DNS record type being validated (e.g., MX, SPF, DKIM).
        status (Status): Result status.
        message (str): Human-readable summary of the outcome.
        details (Dict[str, object]): Structured details for debugging or output.
        optional (bool): Whether the check is for optional records.
        scope (str): Check scope ("required", "optional", "deprecated", "forbidden").
    """

    record_type: str
    status: Status
    message: str
    details: Dict[str, object]
    optional: bool = False
    scope: str = "required"

    def __post_init__(self) -> None:
        """Normalize status and scope values."""
        if not isinstance(self.status, Status):
            self.status = coerce_status(self.status)
        normalized_scope = str(self.scope or "required").lower()
        if self.optional and normalized_scope == "required":
            normalized_scope = "optional"
        if normalized_scope not in _RECORD_SCOPES:
            allowed = ", ".join(sorted(_RECORD_SCOPES))
            raise ValueError(f"RecordCheck scope must be one of: {allowed}")
        self.scope = normalized_scope
        self.optional = normalized_scope == "optional"

    @classmethod
    def with_status(
        cls,
        record_type: str,
        status: Status,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
        scope: Optional[str] = None,
    ) -> "RecordCheck":
        """Build a RecordCheck for a specific status.

        Args:
            record_type (str): DNS record type being validated.
            status (Status): Status to assign.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.
            scope (Optional[str]): Check scope override.

        Returns:
            RecordCheck: Record check result.
        """
        normalized_scope = scope or ("optional" if optional else "required")
        return cls(
            record_type,
            status,
            message,
            details or {},
            optional=optional,
            scope=normalized_scope,
        )

    @classmethod
    def pass_(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
        scope: Optional[str] = None,
    ) -> "RecordCheck":
        """Build a passing RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.
            scope (Optional[str]): Check scope override.

        Returns:
            RecordCheck: Record check result with PASS status.
        """
        return cls.with_status(
            record_type,
            Status.PASS,
            message,
            details,
            optional=optional,
            scope=scope,
        )

    @classmethod
    def warn(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
        scope: Optional[str] = None,
    ) -> "RecordCheck":
        """Build a warning RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.
            scope (Optional[str]): Check scope override.

        Returns:
            RecordCheck: Record check result with WARN status.
        """
        return cls.with_status(
            record_type,
            Status.WARN,
            message,
            details,
            optional=optional,
            scope=scope,
        )

    @classmethod
    def fail(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
        scope: Optional[str] = None,
    ) -> "RecordCheck":
        """Build a failed RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.
            scope (Optional[str]): Check scope override.

        Returns:
            RecordCheck: Record check result with FAIL status.
        """
        return cls.with_status(
            record_type,
            Status.FAIL,
            message,
            details,
            optional=optional,
            scope=scope,
        )

    @classmethod
    def unknown(
        cls,
        record_type: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
        *,
        optional: bool = False,
        scope: Optional[str] = None,
    ) -> "RecordCheck":
        """Build an unknown RecordCheck.

        Args:
            record_type (str): DNS record type being validated.
            message (str): Human-readable summary of the outcome.
            details (Optional[Dict[str, object]]): Structured details for output.
            optional (bool): Whether the check is optional.
            scope (Optional[str]): Check scope override.

        Returns:
            RecordCheck: Record check result with UNKNOWN status.
        """
        return cls.with_status(
            record_type,
            Status.UNKNOWN,
            message,
            details,
            optional=optional,
            scope=scope,
        )
