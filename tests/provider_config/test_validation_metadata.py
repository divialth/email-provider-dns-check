"""Validation tests for provider metadata fields."""

from __future__ import annotations

from collections.abc import Callable

import pytest

INVALID_METADATA_CASES = [
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        short_description:
          - not-a-string
        records: {}
        """,
        "Provider config bad short_description must be a string",
        id="invalid-short-description",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        long_description:
          - not-a-string
        records: {}
        """,
        "Provider config bad long_description must be a string",
        id="invalid-long-description",
    ),
    pytest.param(
        """
        enabled: "false"
        name: Invalid Provider
        version: 1
        records: {}
        """,
        "Provider config enabled must be a boolean",
        id="invalid-enabled-flag",
    ),
]


@pytest.mark.parametrize(("content", "expected_warning"), INVALID_METADATA_CASES)
def test_invalid_metadata_configs_are_rejected(
    content: str,
    expected_warning: str,
    assert_provider_rejected: Callable[[str, str], None],
) -> None:
    """Reject invalid provider metadata payloads with explicit warning checks.

    Args:
        content (str): YAML content to load.
        expected_warning (str): Warning fragment expected from validation.
        assert_provider_rejected (Callable[[str, str], None]): Rejection assertion helper.
    """
    assert_provider_rejected(content, expected_warning)
