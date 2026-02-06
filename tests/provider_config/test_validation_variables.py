"""Validation tests for provider variable configuration."""

from __future__ import annotations

from collections.abc import Callable

import pytest

INVALID_VARIABLE_CASES = [
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables: []
        records: {}
        """,
        "Provider config bad variables must be a mapping",
        id="invalid-variables-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          tenant:
            required: "yes"
        records: {}
        """,
        "Provider config bad variable 'tenant' required must be a boolean",
        id="invalid-variable-required-flag",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          domain:
            required: true
        records: {}
        """,
        "Provider config bad variable 'domain' is reserved and cannot be used",
        id="reserved-variable-name",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          1:
            required: true
        records: {}
        """,
        "Provider config bad variables must use string keys; got 1",
        id="invalid-variable-key-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          "": {}
        records: {}
        """,
        "Provider config bad variables keys must be non-empty",
        id="empty-variable-key",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          token: value
        records: {}
        """,
        "Provider config bad variable 'token' must be a mapping",
        id="invalid-variable-spec-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          token:
            default: 123
        records: {}
        """,
        "Provider config bad variable 'token' default must be a string",
        id="invalid-variable-default-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        variables:
          token:
            description:
              - not-a-string
        records: {}
        """,
        "Provider config bad variable 'token' description must be a string",
        id="invalid-variable-description-type",
    ),
]


@pytest.mark.parametrize(("content", "expected_warning"), INVALID_VARIABLE_CASES)
def test_invalid_variable_configs_are_rejected(
    content: str,
    expected_warning: str,
    assert_provider_rejected: Callable[[str, str], None],
) -> None:
    """Reject invalid provider variable payloads with explicit warning checks.

    Args:
        content (str): YAML content to load.
        expected_warning (str): Warning fragment expected from validation.
        assert_provider_rejected (Callable[[str, str], None]): Rejection assertion helper.
    """
    assert_provider_rejected(content, expected_warning)


def test_variable_null_spec_is_accepted(
    assert_provider_accepted: Callable[[str, str], None],
) -> None:
    """Accept variable entries whose specification is explicitly null.

    Args:
        assert_provider_accepted (Callable[[str, str], None]): Acceptance assertion helper.
    """
    assert_provider_accepted(
        """
        name: Valid Provider
        version: 1
        variables:
          token:
        records: {}
        """,
        provider_id="valid",
    )
