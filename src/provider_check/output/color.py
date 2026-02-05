"""ANSI color helpers for CLI output."""

from __future__ import annotations

import os
import re
from typing import Callable, Mapping, TextIO

from ..status import Status

_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
_ANSI_RESET = "\x1b[0m"
_STATUS_COLORS = {
    Status.PASS.value: "\x1b[32m",
    Status.WARN.value: "\x1b[33m",
    Status.FAIL.value: "\x1b[31m",
    Status.UNKNOWN.value: "\x1b[34m",
}
_FALSEY_ENV_VALUES = {"0", "false", "no", "off"}


def strip_ansi(value: str) -> str:
    """Remove ANSI escape codes from a string.

    Args:
        value (str): Input string.

    Returns:
        str: String without ANSI escape sequences.
    """
    return _ANSI_PATTERN.sub("", value)


def visible_len(value: str) -> int:
    """Return the visible length of a string with ANSI codes.

    Args:
        value (str): Input string.

    Returns:
        int: Length excluding ANSI escape sequences.
    """
    return len(strip_ansi(value))


def make_status_colorizer(enabled: bool) -> Callable[[str], str]:
    """Build a status colorizer based on a flag.

    Args:
        enabled (bool): Whether ANSI colors should be applied.

    Returns:
        Callable[[str], str]: Colorizer function that is safe for any string.
    """
    if not enabled:
        return lambda text: text

    def _colorize(text: str) -> str:
        """Colorize a status string when it matches a known status."""
        code = _STATUS_COLORS.get(text)
        if not code:
            return text
        return f"{code}{text}{_ANSI_RESET}"

    return _colorize


def _parse_env_flag(value: str | None) -> bool:
    """Interpret an environment flag value as a boolean.

    Args:
        value (str | None): Environment value.

    Returns:
        bool: True if the flag should be considered enabled.
    """
    if value is None:
        return False
    if value == "":
        return True
    return value.strip().lower() not in _FALSEY_ENV_VALUES


def _force_color_override(env: Mapping[str, str]) -> bool | None:
    """Return a force-color override if configured.

    Args:
        env (Mapping[str, str]): Environment mapping.

    Returns:
        bool | None: True/False when override is set, otherwise None.
    """
    for key in ("CLICOLOR_FORCE", "FORCE_COLOR"):
        if key in env:
            return _parse_env_flag(env.get(key))
    return None


def resolve_color_enabled(
    mode: str,
    stream: TextIO,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Determine whether ANSI colors should be enabled.

    Args:
        mode (str): Color mode (auto, always, never).
        stream (TextIO): Output stream for TTY detection.
        env (Mapping[str, str] | None): Environment mapping override.

    Returns:
        bool: True if colors should be emitted.
    """
    env = os.environ if env is None else env
    if "NO_COLOR" in env:
        return False
    if mode == "never":
        return False
    if mode == "always":
        return True
    force_override = _force_color_override(env)
    if force_override is not None:
        return force_override
    if env.get("CLICOLOR") == "0":
        return False
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    term = env.get("TERM", "")
    if term.lower() == "dumb":
        return False
    return True
