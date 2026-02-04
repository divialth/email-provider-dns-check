import pytest

import provider_check.provider_config.loader as provider_config


def test_load_provider_caa_records_parsed():
    data = {
        "version": "1",
        "records": {
            "caa": {
                "records": {
                    "@": [
                        {"flags": 0, "tag": "issue", "value": "ca.example.test"},
                        {"flags": 0, "tag": "issuewild", "value": "ca.example.test"},
                    ]
                }
            }
        },
    }

    config = provider_config._load_provider_from_data("caa", data)

    assert config.caa is not None
    assert config.caa.records["@"][0].tag == "issue"
    assert config.caa.records["@"][1].value == "ca.example.test"


def test_load_provider_caa_requires_value():
    data = {
        "version": "1",
        "records": {"caa": {"records": {"@": [{"flags": 0, "tag": "issue"}]}}},
    }

    with pytest.raises(ValueError, match="caa records.@ entries require flags, tag, and value"):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_caa_requires_mapping_entries():
    data = {
        "version": "1",
        "records": {"caa": {"records": {"@": ["not-a-map"]}}},
    }

    with pytest.raises(ValueError, match="caa records.@ entries must be mappings"):
        provider_config._load_provider_from_data("bad", data)
