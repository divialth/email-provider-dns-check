"""Tests for deprecated/forbidden exact/any provider match rules."""

from __future__ import annotations

import pytest


def test_load_provider_negative_match_rules(provider_config_loader) -> None:
    """Parse exact/any negative rules across supported record sections."""
    data = {
        "version": "1",
        "records": {
            "mx": {
                "required": [],
                "deprecated": {
                    "policy": {"match": "exact"},
                    "entries": [{"host": "legacy.mx.example.test.", "priority": 5}],
                },
                "forbidden": {"policy": {"match": "any"}},
            },
            "a": {
                "required": {},
                "deprecated": {"legacy": ["192.0.2.9"]},
                "forbidden": {"blocked": {"match": "any"}},
            },
            "aaaa": {
                "required": {},
                "deprecated": {"legacy6": {"match": "exact", "values": ["2001:db8::9"]}},
                "forbidden": {"blocked6": {"match": "any"}},
            },
            "ptr": {
                "required": {},
                "deprecated": {"10.2.0.192.in-addr.arpa.": ["legacy.example.test."]},
                "forbidden": {"11.2.0.192.in-addr.arpa.": {"match": "any"}},
            },
            "cname": {
                "required": {},
                "deprecated": {"legacy": "legacy.provider.test."},
                "forbidden": {"blocked": {"match": "any"}},
            },
            "caa": {
                "required": {},
                "deprecated": {"@": [{"flags": 0, "tag": "issue", "value": "legacy.example"}]},
                "forbidden": {"@": {"match": "any"}},
            },
            "srv": {
                "required": {},
                "deprecated": {
                    "_sip._tls": {
                        "match": "exact",
                        "entries": [
                            {
                                "priority": 100,
                                "weight": 1,
                                "port": 443,
                                "target": "legacy.srv.example.",
                            }
                        ],
                    }
                },
                "forbidden": {
                    "_sip._tcp": [
                        {"priority": 1, "weight": 1, "port": 443, "target": "forbid.srv."}
                    ],
                    "_sip._ws": {"match": "any"},
                },
            },
            "tlsa": {
                "required": {},
                "deprecated": {
                    "_25._tcp.mail": [
                        {
                            "usage": 3,
                            "selector": 1,
                            "matching_type": 1,
                            "certificate_association": "abc123",
                        }
                    ]
                },
                "forbidden": {"_443._tcp.mail": {"match": "any"}},
            },
            "txt": {
                "required": {},
                "deprecated": {"_legacy": {"match": "exact", "values": ["legacy=true"]}},
                "forbidden": {"_blocked": {"match": "any"}},
            },
        },
    }

    config = provider_config_loader._load_provider_from_data("negative", data)

    assert config.mx is not None
    assert config.mx.deprecated.policy.match == "exact"
    assert config.mx.deprecated.entries[0].host == "legacy.mx.example.test."
    assert config.mx.forbidden.policy.match == "any"
    assert config.mx.forbidden.entries == []
    assert config.a is not None
    assert config.a.deprecated["legacy"].match == "exact"
    assert config.a.forbidden["blocked"].match == "any"
    assert config.aaaa is not None
    assert config.aaaa.deprecated["legacy6"].values == ["2001:db8::9"]
    assert config.ptr is not None
    assert config.ptr.forbidden["11.2.0.192.in-addr.arpa."].match == "any"
    assert config.cname is not None
    assert config.cname.deprecated["legacy"].target == "legacy.provider.test."
    assert config.caa is not None
    assert config.caa.forbidden["@"].match == "any"
    assert config.srv is not None
    assert config.srv.deprecated["_sip._tls"].entries[0].target == "legacy.srv.example."
    assert config.srv.forbidden["_sip._ws"].match == "any"
    assert config.tlsa is not None
    assert config.tlsa.deprecated["_25._tcp.mail"].entries[0].certificate_association == "abc123"
    assert config.txt is not None
    assert config.txt.deprecated["_legacy"].values == ["legacy=true"]


def test_load_provider_negative_rule_rejects_invalid_match_mode(provider_config_loader) -> None:
    """Reject invalid match mode values."""
    data = {
        "version": "1",
        "records": {"txt": {"required": {}, "deprecated": {"_legacy": {"match": "bad"}}}},
    }

    with pytest.raises(ValueError, match="match must be one of"):
        provider_config_loader._load_provider_from_data("negative", data)


def test_load_provider_mx_negative_empty_blocks_are_allowed(provider_config_loader) -> None:
    """Allow explicit empty MX deprecated/forbidden blocks as no-op."""
    data = {
        "version": "1",
        "records": {
            "mx": {
                "required": [],
                "deprecated": {},
                "forbidden": {},
            }
        },
    }

    config = provider_config_loader._load_provider_from_data("negative", data)

    assert config.mx is not None
    assert config.mx.deprecated.policy.match == "exact"
    assert config.mx.deprecated.entries == []
    assert config.mx.forbidden.policy.match == "exact"
    assert config.mx.forbidden.entries == []


@pytest.mark.parametrize(
    ("records", "message"),
    [
        (
            {
                "mx": {
                    "required": [],
                    "deprecated": {
                        "entries": [],
                    },
                }
            },
            "exact policy requires at least one entry",
        ),
        (
            {
                "mx": {
                    "required": [],
                    "deprecated": {
                        "policy": {"match": "exact"},
                    },
                }
            },
            "exact policy requires at least one entry",
        ),
        (
            {
                "mx": {
                    "required": [],
                    "deprecated": {
                        "policy": {"match": "exact"},
                        "entries": [],
                    },
                }
            },
            "exact policy requires at least one entry",
        ),
        (
            {
                "mx": {
                    "required": [],
                    "deprecated": {
                        "policy": {"match": "any"},
                        "entries": [{"host": "legacy.mx.example.test."}],
                    },
                }
            },
            "entries are not allowed when policy.match is any",
        ),
        (
            {"txt": {"required": {}, "deprecated": {"_legacy": {"match": "exact", "values": []}}}},
            "exact rules require at least one value",
        ),
        (
            {"cname": {"required": {}, "forbidden": {"legacy": {"match": "exact"}}}},
            "exact rules require a string target",
        ),
        (
            {"caa": {"required": {}, "deprecated": {"@": {"match": "exact", "entries": []}}}},
            "exact rules require at least one entry",
        ),
        (
            {
                "srv": {
                    "required": {},
                    "deprecated": {"_sip._tls": {"match": "exact", "entries": []}},
                }
            },
            "exact rules require at least one entry",
        ),
        (
            {
                "tlsa": {
                    "required": {},
                    "deprecated": {"_25._tcp.mail": {"match": "exact", "entries": []}},
                }
            },
            "exact rules require at least one entry",
        ),
    ],
)
def test_load_provider_negative_rule_rejects_empty_exact_records(
    provider_config_loader,
    records: dict,
    message: str,
) -> None:
    """Reject empty exact-match rule payloads."""
    data = {"version": "1", "records": records}

    with pytest.raises(ValueError, match=message):
        provider_config_loader._load_provider_from_data("negative", data)
