"""Schema-contract tests for provider record parser keys."""

from __future__ import annotations

from dataclasses import fields

import pytest

from provider_check.provider_config import (
    AddressConfig,
    CAAConfig,
    CNAMEConfig,
    DKIMConfig,
    DKIMRequired,
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    MXConfig,
    PTRConfig,
    SPFConfig,
    SPFOptional,
    SPFRequired,
    SRVConfig,
    TXTConfig,
    TXTSettings,
)
from provider_check.provider_config.loader.parse.schema import RECORD_SCHEMA


def _field_names(model: type) -> set[str]:
    """Return dataclass field names for a model type.

    Args:
        model (type): Dataclass model type.

    Returns:
        set[str]: Field names.
    """
    return {entry.name for entry in fields(model)}


@pytest.mark.parametrize(
    ("record_type", "config_model"),
    [
        ("mx", MXConfig),
        ("spf", SPFConfig),
        ("dkim", DKIMConfig),
        ("a", AddressConfig),
        ("aaaa", AddressConfig),
        ("ptr", PTRConfig),
        ("cname", CNAMEConfig),
        ("caa", CAAConfig),
        ("srv", SRVConfig),
        ("txt", TXTConfig),
        ("dmarc", DMARCConfig),
    ],
)
def test_record_section_keys_match_config_models(record_type: str, config_model: type) -> None:
    """Keep parser section keys aligned with provider config dataclasses.

    Args:
        record_type (str): Record schema key.
        config_model (type): Dataclass model to compare.
    """
    assert set(RECORD_SCHEMA[record_type]["section"]) == _field_names(config_model)


@pytest.mark.parametrize(
    ("record_type", "section_name", "section_model"),
    [
        ("spf", "required", SPFRequired),
        ("spf", "optional", SPFOptional),
        ("dkim", "required", DKIMRequired),
        ("dmarc", "required", DMARCRequired),
        ("dmarc", "optional", DMARCOptional),
        ("dmarc", "settings", DMARCSettings),
        ("txt", "settings", TXTSettings),
    ],
)
def test_record_nested_keys_match_section_models(
    record_type: str, section_name: str, section_model: type
) -> None:
    """Keep parser nested section keys aligned with nested dataclasses.

    Args:
        record_type (str): Record schema key.
        section_name (str): Section within the record schema.
        section_model (type): Dataclass model to compare.
    """
    assert set(RECORD_SCHEMA[record_type][section_name]) == _field_names(section_model)


def test_record_nested_sections_are_explicit_and_bounded() -> None:
    """Ensure only expected records expose nested structured section key lists."""
    expected = {
        "mx": set(),
        "spf": {"required", "optional"},
        "dkim": {"required"},
        "a": set(),
        "aaaa": set(),
        "ptr": set(),
        "cname": set(),
        "caa": set(),
        "srv": set(),
        "txt": {"settings"},
        "dmarc": {"required", "optional", "settings"},
    }
    for record_type, section_schema in RECORD_SCHEMA.items():
        assert set(section_schema.keys()) - {"section"} == expected[record_type]


def test_required_sections_forbid_raw_record_string_keys() -> None:
    """Enforce structured strict controls by forbidding ``required.record`` keys."""
    for section_schema in RECORD_SCHEMA.values():
        required_keys = set(section_schema.get("required", frozenset()))
        assert "record" not in required_keys


def test_spf_required_uses_structured_policy_field() -> None:
    """Ensure SPF strict controls are represented by structured fields only."""
    spf_fields = _field_names(SPFRequired)
    assert "policy" in spf_fields
    assert "record" not in spf_fields
