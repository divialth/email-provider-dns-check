"""Shared status constants and exit code mapping."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Union


class Status(Enum):
    """Known result statuses."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ExitCodes:
    """Exit codes aligned with status values.

    Attributes:
        PASS (int): Exit code for passing checks.
        WARN (int): Exit code for warnings.
        FAIL (int): Exit code for failed checks.
        UNKNOWN (int): Exit code for unknown/ambiguous results.
    """

    PASS: int = 0
    WARN: int = 1
    FAIL: int = 2
    UNKNOWN: int = 3


def coerce_status(status: Union[Status, str]) -> Status:
    """Normalize a status string or enum into a Status value.

    Args:
        status (Status | str): Status enum or string value.

    Returns:
        Status: Normalized Status value.
    """
    if isinstance(status, Status):
        return status
    try:
        return Status(status)
    except ValueError:
        return Status.UNKNOWN


def exit_code_for_status(status: Union[Status, str]) -> int:
    """Map a status value to an exit code.

    Args:
        status (Status | str): Status enum or string value.

    Returns:
        int: Exit code for the status.
    """
    normalized = coerce_status(status)
    if normalized is Status.PASS:
        return ExitCodes.PASS
    if normalized is Status.WARN:
        return ExitCodes.WARN
    if normalized is Status.FAIL:
        return ExitCodes.FAIL
    return ExitCodes.UNKNOWN


__all__ = ["ExitCodes", "Status", "coerce_status", "exit_code_for_status"]
