"""Parsing helpers for CLI inputs."""

from __future__ import annotations

import argparse
from typing import List


def _parse_txt_records(raw_records: List[str]) -> dict[str, list[str]]:
    """Parse TXT record requirements from CLI values.

    Args:
        raw_records (List[str]): Values in name=value form.

    Returns:
        dict[str, list[str]]: Parsed TXT values by name.

    Raises:
        ValueError: If any value is missing a name or value.
    """
    required: dict[str, list[str]] = {}
    for item in raw_records:
        if "=" not in item:
            raise ValueError(f"TXT record '{item}' must be in name=value form")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"TXT record '{item}' must include both name and value")
        required.setdefault(name, []).append(value)
    return required


def _parse_dmarc_pct(value: str) -> int:
    """Parse a DMARC pct value from CLI input.

    Args:
        value (str): String value to parse.

    Returns:
        int: Parsed percentage between 0 and 100.

    Raises:
        argparse.ArgumentTypeError: If the value is invalid or out of range.
    """
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("DMARC pct must be an integer between 0 and 100") from exc
    if parsed < 0 or parsed > 100:
        raise argparse.ArgumentTypeError("DMARC pct must be between 0 and 100")
    return parsed


def _parse_provider_vars(raw_vars: List[str]) -> dict[str, str]:
    """Parse provider variables from CLI values.

    Args:
        raw_vars (List[str]): Values in name=value form.

    Returns:
        dict[str, str]: Parsed variables mapping.

    Raises:
        ValueError: If any variable is malformed or duplicated.
    """
    parsed: dict[str, str] = {}
    for item in raw_vars:
        if "=" not in item:
            raise ValueError(f"Provider variable '{item}' must be in name=value form")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"Provider variable '{item}' must include both name and value")
        if name in parsed:
            raise ValueError(f"Provider variable '{name}' was provided more than once")
        parsed[name] = value
    return parsed
