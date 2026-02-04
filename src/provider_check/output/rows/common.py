"""Row helper utilities."""

from __future__ import annotations


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
