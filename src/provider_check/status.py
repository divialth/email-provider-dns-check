"""Shared status constants and exit code mapping."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


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


def exit_code_for_status(status: str) -> int:
    """Map a status string to an exit code.

    Args:
        status (str): Status string.

    Returns:
        int: Exit code for the status.
    """
    if status == Status.PASS.value:
        return ExitCodes.PASS
    if status == Status.WARN.value:
        return ExitCodes.WARN
    if status == Status.FAIL.value:
        return ExitCodes.FAIL
    return ExitCodes.UNKNOWN


__all__ = ["ExitCodes", "Status", "exit_code_for_status"]
