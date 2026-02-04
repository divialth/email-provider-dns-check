"""Shared helpers for DNS checker logic."""

from __future__ import annotations

SPF_QUALIFIERS = {"-", "~", "?"}


def strip_spf_qualifier(token: str) -> tuple[str, str]:
    """Split an SPF token into base value and qualifier.

    Args:
        token (str): SPF token (e.g., "-all", "~ip4:1.2.3.4").

    Returns:
        tuple[str, str]: (base, qualifier) where qualifier may be empty.
    """
    if token and token[0] in {"+", *SPF_QUALIFIERS}:
        return token[1:], token[0]
    return token, ""
