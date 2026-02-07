"""Validation tests for provider record sections."""

from __future__ import annotations

from collections.abc import Callable

import pytest

INVALID_RECORD_CASES = [
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records: []
        """,
        "Provider config bad records must be a mapping",
        id="invalid-records-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          spf:
            required:
              policy: hardfail
              includes: example.test
        """,
        "Provider config bad spf required includes must be a list",
        id="invalid-spf-includes-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            settings:
              verification_required: "false"
        """,
        "Provider config bad txt settings.verification_required must be a boolean",
        id="invalid-txt-verification-required-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            required:
              _verify: token
        """,
        "Provider config bad txt required._verify must be a list",
        id="invalid-txt-required-values",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            optional:
              _verify: token
        """,
        "Provider config bad txt optional._verify must be a list",
        id="invalid-txt-optional-values",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          a:
            required:
              "@": 192.0.2.1
        """,
        "Provider config bad a required.@ must be a list",
        id="invalid-a-record-values",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          aaaa:
            required:
              "@": 2001:db8::1
        """,
        "Provider config bad aaaa required.@ must be a list",
        id="invalid-aaaa-record-values",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          cname:
            required:
              - not-a-map
        """,
        "Provider config bad cname required must be a mapping",
        id="invalid-cname-required-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          cname:
            required:
              sip:
                target: sip.provider.test.
        """,
        "Provider config bad cname required 'sip' must be a string",
        id="invalid-cname-value-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls: invalid
        """,
        "Provider config bad srv required._sip._tls must be a list",
        id="invalid-srv-entry-list-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls:
                - target: sip.provider.test.
        """,
        "Provider config bad srv required._sip._tls entries require priority, weight, port, and target",
        id="invalid-srv-entry-missing-fields",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls:
                - not-a-map
        """,
        "Provider config bad srv required._sip._tls entries must be mappings",
        id="invalid-srv-entry-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          dmarc:
            settings:
              rua_required: "false"
        """,
        "Provider config bad dmarc settings.rua_required must be a boolean",
        id="invalid-dmarc-rua-required-type",
    ),
    pytest.param(
        """
        name: Invalid Provider
        version: 1
        records:
          dmarc:
            settings:
              ruf_required: "false"
        """,
        "Provider config bad dmarc settings.ruf_required must be a boolean",
        id="invalid-dmarc-ruf-required-type",
    ),
]


@pytest.mark.parametrize(("content", "expected_warning"), INVALID_RECORD_CASES)
def test_invalid_record_configs_are_rejected(
    content: str,
    expected_warning: str,
    assert_provider_rejected: Callable[[str, str], None],
) -> None:
    """Reject invalid provider record payloads with explicit warning checks.

    Args:
        content (str): YAML content to load.
        expected_warning (str): Warning fragment expected from validation.
        assert_provider_rejected (Callable[[str, str], None]): Rejection assertion helper.
    """
    assert_provider_rejected(content, expected_warning)
