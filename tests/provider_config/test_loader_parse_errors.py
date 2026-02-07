"""Provider config parser and low-level loader tests."""

from __future__ import annotations

import pytest


def test_require_mapping_rejects_missing_or_invalid(provider_config_loader) -> None:
    """Reject missing and invalid mappings."""
    with pytest.raises(ValueError):
        provider_config_loader._require_mapping("dummy", "records", None)
    with pytest.raises(ValueError):
        provider_config_loader._require_mapping("dummy", "records", [])


def test_require_list_rejects_missing_or_invalid(provider_config_loader) -> None:
    """Reject missing and invalid lists."""
    with pytest.raises(ValueError):
        provider_config_loader._require_list("dummy", "mx hosts", None)
    with pytest.raises(ValueError):
        provider_config_loader._require_list("dummy", "mx hosts", {})


def test_load_yaml_requires_mapping(provider_config_loader, tmp_path) -> None:
    """Reject YAML documents that are not mappings."""
    path = tmp_path / "invalid.yaml"
    path.write_text("- item", encoding="utf-8")

    with pytest.raises(ValueError):
        provider_config_loader._load_yaml(path)


def test_load_provider_missing_version_raises(provider_config_loader) -> None:
    """Require provider version during loading."""
    with pytest.raises(ValueError):
        provider_config_loader._load_provider_from_data("bad", {"name": "Bad", "records": {}})


def test_load_provider_records_optional(provider_config_loader) -> None:
    """Allow providers without an explicit records section."""
    data = {"version": "1", "name": "Optional Records"}

    config = provider_config_loader._load_provider_from_data("optional", data)

    assert config.mx is None
    assert config.spf is None


def test_load_provider_mx_record_requires_mapping(provider_config_loader) -> None:
    """Require MX entries to be mappings."""
    data = {
        "version": "1",
        "records": {"mx": {"required": ["not-a-map"]}},
    }

    with pytest.raises(ValueError):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_mx_record_requires_host(provider_config_loader) -> None:
    """Require MX records to include a host field."""
    data = {
        "version": "1",
        "records": {"mx": {"required": [{}]}},
    }

    with pytest.raises(ValueError):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_mx_records_parsed(provider_config_loader) -> None:
    """Parse required and optional MX records."""
    data = {
        "version": "1",
        "records": {
            "mx": {
                "required": [{"host": "mx1.example.", "priority": 10}],
                "optional": [{"host": "mx2.example."}],
            }
        },
    }

    config = provider_config_loader._load_provider_from_data("mx", data)

    assert config.mx is not None
    assert config.mx.required[0].host == "mx1.example."
    assert config.mx.required[0].priority == 10
    assert config.mx.optional[0].host == "mx2.example."
    assert config.mx.optional[0].priority is None


def test_load_provider_spf_policy_requires_string(provider_config_loader) -> None:
    """Require SPF policy values to be strings."""
    data = {
        "version": "1",
        "records": {"spf": {"required": {"policy": 123}}},
    }

    with pytest.raises(ValueError, match="spf required policy must be a string"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_spf_policy_requires_supported_value(provider_config_loader) -> None:
    """Require SPF policy values to be supported keywords."""
    data = {
        "version": "1",
        "records": {"spf": {"required": {"policy": "invalid"}}},
    }

    with pytest.raises(ValueError, match="spf required policy must be one of"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_spf_record_key_rejected(provider_config_loader) -> None:
    """Reject legacy SPF required.record schema usage."""
    data = {
        "version": "1",
        "records": {"spf": {"required": {"record": "v=spf1 include:example.test -all"}}},
    }

    with pytest.raises(ValueError, match="spf required has unknown keys: record"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_dkim_record_type_invalid(provider_config_loader) -> None:
    """Reject unsupported DKIM record types."""
    data = {
        "version": "1",
        "records": {"dkim": {"required": {"selectors": ["s1"], "record_type": "invalid"}}},
    }

    with pytest.raises(ValueError, match="dkim record_type must be cname or txt"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_dkim_cname_requires_target_template(provider_config_loader) -> None:
    """Require DKIM CNAME target template."""
    data = {
        "version": "1",
        "records": {"dkim": {"required": {"selectors": ["s1"], "record_type": "cname"}}},
    }

    with pytest.raises(ValueError, match="dkim requires target_template for cname"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_dmarc_policy_requires_string(provider_config_loader) -> None:
    """Require DMARC policy values to be strings."""
    data = {
        "version": "1",
        "records": {"dmarc": {"required": {"policy": 123}}},
    }

    with pytest.raises(ValueError, match="dmarc required policy must be a string"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_dmarc_policy_rejects_null(provider_config_loader) -> None:
    """Reject null DMARC policy values."""
    data = {
        "version": "1",
        "records": {"dmarc": {"required": {"policy": None}}},
    }

    with pytest.raises(ValueError, match="dmarc required policy must be a string"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_cname_optional_requires_string(provider_config_loader) -> None:
    """Require optional CNAME values to be strings."""
    data = {
        "version": "1",
        "records": {"cname": {"optional": {"autoconfig": {"bad": "value"}}}},
    }

    with pytest.raises(ValueError, match="cname optional 'autoconfig' must be a string"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_srv_optional_requires_mapping_entries(provider_config_loader) -> None:
    """Require optional SRV entries to be mappings."""
    data = {
        "version": "1",
        "records": {"srv": {"optional": {"_autodiscover._tcp": ["not-a-map"]}}},
    }

    with pytest.raises(ValueError, match="srv optional._autodiscover._tcp entries"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_srv_optional_requires_priority_fields(provider_config_loader) -> None:
    """Require optional SRV entries to include required fields."""
    data = {
        "version": "1",
        "records": {"srv": {"optional": {"_autodiscover._tcp": [{"priority": 0, "weight": 0}]}}},
    }

    with pytest.raises(ValueError, match="srv optional._autodiscover._tcp entries require"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_records_unknown_type_rejected(provider_config_loader) -> None:
    """Reject unknown record type sections."""
    data = {
        "version": "1",
        "records": {"bogus": {}},
    }

    with pytest.raises(ValueError, match="records has unknown keys: bogus"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_txt_records_loaded(provider_config_loader) -> None:
    """Load required TXT records."""
    data = {
        "version": "1",
        "records": {"txt": {"required": {"_verify": ["token-1", "token-2"]}}},
    }

    config = provider_config_loader._load_provider_from_data("txt", data)

    assert config.txt is not None
    assert config.txt.required == {"_verify": ["token-1", "token-2"]}


def test_load_provider_txt_unknown_key_rejected(provider_config_loader) -> None:
    """Reject unknown keys in TXT sections."""
    data = {
        "version": "1",
        "records": {"txt": {"required": {"_verify": ["token-1"]}, "extra": True}},
    }

    with pytest.raises(ValueError, match="txt has unknown keys: extra"):
        provider_config_loader._load_provider_from_data("txt", data)


def test_load_provider_txt_optional_records_loaded(provider_config_loader) -> None:
    """Load optional TXT records."""
    data = {
        "version": "1",
        "records": {
            "txt": {
                "required": {"_verify": ["token-1"]},
                "optional": {"_optional": ["token-2"]},
            }
        },
    }

    config = provider_config_loader._load_provider_from_data("txt", data)

    assert config.txt is not None
    assert config.txt.optional == {"_optional": ["token-2"]}


def test_load_provider_variable_unknown_key_rejected(provider_config_loader) -> None:
    """Reject unknown keys in variable definitions."""
    data = {
        "version": "1",
        "variables": {"tenant": {"required": True, "extra": "value"}},
    }

    with pytest.raises(ValueError, match="variable 'tenant' has unknown keys: extra"):
        provider_config_loader._load_provider_from_data("bad", data)


def test_load_provider_address_records_loaded(provider_config_loader) -> None:
    """Load A and AAAA address records."""
    data = {
        "version": "1",
        "records": {
            "a": {
                "required": {"@": ["192.0.2.1"]},
                "optional": {"autodiscover": ["192.0.2.2"]},
            },
            "aaaa": {
                "required": {"@": ["2001:db8::1"]},
                "optional": {"autodiscover": ["2001:db8::2"]},
            },
        },
    }

    config = provider_config_loader._load_provider_from_data("address", data)

    assert config.a is not None
    assert config.a.required == {"@": ["192.0.2.1"]}
    assert config.a.optional == {"autodiscover": ["192.0.2.2"]}
    assert config.aaaa is not None
    assert config.aaaa.required == {"@": ["2001:db8::1"]}
    assert config.aaaa.optional == {"autodiscover": ["2001:db8::2"]}
