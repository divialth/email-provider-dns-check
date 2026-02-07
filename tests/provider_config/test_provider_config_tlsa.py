"""Provider-config tests for TLSA record parsing."""

from __future__ import annotations

import pytest

import provider_check.provider_config.loader as provider_config


def test_load_provider_tlsa_records_parsed() -> None:
    """Parse required and optional TLSA records."""
    data = {
        "version": "1",
        "records": {
            "tlsa": {
                "required": {
                    "_25._tcp.mail": [
                        {
                            "usage": 3,
                            "selector": 1,
                            "matching_type": 1,
                            "certificate_association": "abc123",
                        }
                    ]
                },
                "optional": {
                    "_443._tcp.autodiscover": [
                        {
                            "usage": 3,
                            "selector": 1,
                            "matching_type": 1,
                            "certificate_association": "def456",
                        }
                    ]
                },
            }
        },
    }

    config = provider_config._load_provider_from_data("tlsa", data)

    assert config.tlsa is not None
    assert config.tlsa.required["_25._tcp.mail"][0].usage == 3
    assert config.tlsa.required["_25._tcp.mail"][0].matching_type == 1
    assert config.tlsa.optional["_443._tcp.autodiscover"][0].certificate_association == "def456"


def test_load_provider_tlsa_requires_certificate_association() -> None:
    """Require TLSA entries to include certificate association data."""
    data = {
        "version": "1",
        "records": {
            "tlsa": {
                "required": {
                    "_25._tcp.mail": [
                        {
                            "usage": 3,
                            "selector": 1,
                            "matching_type": 1,
                        }
                    ]
                }
            }
        },
    }

    with pytest.raises(
        ValueError,
        match=(
            "tlsa required._25._tcp.mail entries require usage, selector, matching_type, "
            "and certificate_association"
        ),
    ):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_tlsa_requires_mapping_entries() -> None:
    """Require TLSA entries to be mappings."""
    data = {
        "version": "1",
        "records": {"tlsa": {"required": {"_25._tcp.mail": ["not-a-map"]}}},
    }

    with pytest.raises(ValueError, match="tlsa required._25._tcp.mail entries must be mappings"):
        provider_config._load_provider_from_data("bad", data)
