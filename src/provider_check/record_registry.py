"""Record type registry shared by checks, output, and detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


class _CheckerView:
    """Minimal checker interface for registry predicates.

    Attributes:
        provider (object): Provider configuration object.
        additional_txt (dict): Additional TXT requirements.
        additional_txt_verification (dict): Additional TXT verification requirements.
    """

    provider: object
    additional_txt: dict
    additional_txt_verification: dict


@dataclass(frozen=True)
class CheckSpec:
    """Describe a check method and when it should run.

    Attributes:
        record_type (str): Record type label (e.g., MX, SPF).
        check_method (str): DNSChecker method name.
        enabled_when (Callable[[_CheckerView], bool]): Predicate for enabling the check.
    """

    record_type: str
    check_method: str
    enabled_when: Callable[[_CheckerView], bool]


@dataclass(frozen=True)
class RecordTypeSpec:
    """Describe record type metadata.

    Attributes:
        record_type (str): Record type label (e.g., MX, SPF).
        weight (int): Detection scoring weight.
        core (bool): Whether the record type is considered core for detection.
        row_builder_name (str): Output row builder function name.
    """

    record_type: str
    weight: int
    core: bool
    row_builder_name: str


def _has_required_records(value: Optional[object]) -> bool:
    """Return True when a config object has required records.

    Args:
        value (Optional[object]): Provider config section.

    Returns:
        bool: True if required records are present.
    """

    return bool(value and getattr(value, "required", None))


def _has_optional_records(value: Optional[object]) -> bool:
    """Return True when a config object has optional records.

    Args:
        value (Optional[object]): Provider config section.

    Returns:
        bool: True if optional records are present.
    """

    return bool(value and getattr(value, "optional", None))


def _has_deprecated_records(value: Optional[object]) -> bool:
    """Return True when a config object has deprecated records.

    Args:
        value (Optional[object]): Provider config section.

    Returns:
        bool: True if deprecated records are present.
    """

    return bool(value and getattr(value, "deprecated", None))


def _has_forbidden_records(value: Optional[object]) -> bool:
    """Return True when a config object has forbidden records.

    Args:
        value (Optional[object]): Provider config section.

    Returns:
        bool: True if forbidden records are present.
    """

    return bool(value and getattr(value, "forbidden", None))


def _enabled_mx(checker: _CheckerView) -> bool:
    """Enable MX checks when the provider defines MX rules.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if MX checks should run.
    """

    return _has_required_records(getattr(checker.provider, "mx", None))


def _enabled_mx_optional(checker: _CheckerView) -> bool:
    """Enable optional MX checks when optional MX records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional MX checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "mx", None))


def _has_mx_negative_rules(value: Optional[object], *, field_name: str) -> bool:
    """Return True when MX negative rules are effectively configured.

    Args:
        value (Optional[object]): MX config object.
        field_name (str): MX negative field name ("deprecated" or "forbidden").

    Returns:
        bool: True if rules are configured.
    """
    if not value:
        return False
    rules = getattr(value, field_name, None)
    if not rules:
        return False
    policy = getattr(rules, "policy", None)
    mode = str(getattr(policy, "match", "exact")).lower()
    if mode == "any":
        return True
    return bool(getattr(rules, "entries", None))


def _enabled_mx_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated MX checks when deprecated MX rules are present."""

    return _has_mx_negative_rules(getattr(checker.provider, "mx", None), field_name="deprecated")


def _enabled_mx_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden MX checks when forbidden MX rules are present."""

    return _has_mx_negative_rules(getattr(checker.provider, "mx", None), field_name="forbidden")


def _enabled_spf(checker: _CheckerView) -> bool:
    """Enable SPF checks when the provider defines SPF rules.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if SPF checks should run.
    """

    return bool(getattr(checker.provider, "spf", None))


def _enabled_dkim(checker: _CheckerView) -> bool:
    """Enable DKIM checks when the provider defines DKIM rules.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if DKIM checks should run.
    """

    return bool(getattr(checker.provider, "dkim", None))


def _enabled_a(checker: _CheckerView) -> bool:
    """Enable A checks when required A records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if A checks should run.
    """

    return _has_required_records(getattr(checker.provider, "a", None))


def _enabled_a_optional(checker: _CheckerView) -> bool:
    """Enable optional A checks when optional A records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional A checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "a", None))


def _enabled_a_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated A checks when deprecated A records are present."""

    return _has_deprecated_records(getattr(checker.provider, "a", None))


def _enabled_a_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden A checks when forbidden A records are present."""

    return _has_forbidden_records(getattr(checker.provider, "a", None))


def _enabled_aaaa(checker: _CheckerView) -> bool:
    """Enable AAAA checks when required AAAA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if AAAA checks should run.
    """

    return _has_required_records(getattr(checker.provider, "aaaa", None))


def _enabled_aaaa_optional(checker: _CheckerView) -> bool:
    """Enable optional AAAA checks when optional AAAA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional AAAA checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "aaaa", None))


def _enabled_aaaa_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated AAAA checks when deprecated AAAA records are present."""

    return _has_deprecated_records(getattr(checker.provider, "aaaa", None))


def _enabled_aaaa_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden AAAA checks when forbidden AAAA records are present."""

    return _has_forbidden_records(getattr(checker.provider, "aaaa", None))


def _enabled_ptr(checker: _CheckerView) -> bool:
    """Enable PTR checks when required PTR records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if PTR checks should run.
    """

    return _has_required_records(getattr(checker.provider, "ptr", None))


def _enabled_ptr_optional(checker: _CheckerView) -> bool:
    """Enable optional PTR checks when optional PTR records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional PTR checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "ptr", None))


def _enabled_ptr_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated PTR checks when deprecated PTR records are present."""

    return _has_deprecated_records(getattr(checker.provider, "ptr", None))


def _enabled_ptr_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden PTR checks when forbidden PTR records are present."""

    return _has_forbidden_records(getattr(checker.provider, "ptr", None))


def _enabled_cname(checker: _CheckerView) -> bool:
    """Enable CNAME checks when required CNAME records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if CNAME checks should run.
    """

    return _has_required_records(getattr(checker.provider, "cname", None))


def _enabled_cname_optional(checker: _CheckerView) -> bool:
    """Enable optional CNAME checks when optional CNAME records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional CNAME checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "cname", None))


def _enabled_cname_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated CNAME checks when deprecated CNAME records are present."""

    return _has_deprecated_records(getattr(checker.provider, "cname", None))


def _enabled_cname_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden CNAME checks when forbidden CNAME records are present."""

    return _has_forbidden_records(getattr(checker.provider, "cname", None))


def _enabled_caa(checker: _CheckerView) -> bool:
    """Enable CAA checks when required CAA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if CAA checks should run.
    """

    return _has_required_records(getattr(checker.provider, "caa", None))


def _enabled_caa_optional(checker: _CheckerView) -> bool:
    """Enable optional CAA checks when optional CAA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional CAA checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "caa", None))


def _enabled_caa_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated CAA checks when deprecated CAA records are present."""

    return _has_deprecated_records(getattr(checker.provider, "caa", None))


def _enabled_caa_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden CAA checks when forbidden CAA records are present."""

    return _has_forbidden_records(getattr(checker.provider, "caa", None))


def _enabled_srv(checker: _CheckerView) -> bool:
    """Enable SRV checks when required SRV records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if SRV checks should run.
    """

    return _has_required_records(getattr(checker.provider, "srv", None))


def _enabled_srv_optional(checker: _CheckerView) -> bool:
    """Enable optional SRV checks when optional SRV records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional SRV checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "srv", None))


def _enabled_srv_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated SRV checks when deprecated SRV records are present."""

    return _has_deprecated_records(getattr(checker.provider, "srv", None))


def _enabled_srv_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden SRV checks when forbidden SRV records are present."""

    return _has_forbidden_records(getattr(checker.provider, "srv", None))


def _enabled_txt(checker: _CheckerView) -> bool:
    """Enable TXT checks when provider or extra TXT requirements exist.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if TXT checks should run.
    """

    return bool(
        getattr(checker.provider, "txt", None)
        or checker.additional_txt
        or checker.additional_txt_verification
    )


def _enabled_tlsa(checker: _CheckerView) -> bool:
    """Enable TLSA checks when required TLSA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if TLSA checks should run.
    """

    return _has_required_records(getattr(checker.provider, "tlsa", None))


def _enabled_tlsa_optional(checker: _CheckerView) -> bool:
    """Enable optional TLSA checks when optional TLSA records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional TLSA checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "tlsa", None))


def _enabled_tlsa_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated TLSA checks when deprecated TLSA records are present."""

    return _has_deprecated_records(getattr(checker.provider, "tlsa", None))


def _enabled_tlsa_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden TLSA checks when forbidden TLSA records are present."""

    return _has_forbidden_records(getattr(checker.provider, "tlsa", None))


def _enabled_txt_optional(checker: _CheckerView) -> bool:
    """Enable optional TXT checks when optional TXT records are present.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if optional TXT checks should run.
    """

    return _has_optional_records(getattr(checker.provider, "txt", None))


def _enabled_txt_deprecated(checker: _CheckerView) -> bool:
    """Enable deprecated TXT checks when deprecated TXT records are present."""

    return _has_deprecated_records(getattr(checker.provider, "txt", None))


def _enabled_txt_forbidden(checker: _CheckerView) -> bool:
    """Enable forbidden TXT checks when forbidden TXT records are present."""

    return _has_forbidden_records(getattr(checker.provider, "txt", None))


def _enabled_dmarc(checker: _CheckerView) -> bool:
    """Enable DMARC checks when the provider defines DMARC rules.

    Args:
        checker (_CheckerView): Checker instance to inspect.

    Returns:
        bool: True if DMARC checks should run.
    """

    return bool(getattr(checker.provider, "dmarc", None))


CHECK_SPECS: tuple[CheckSpec, ...] = (
    CheckSpec("MX", "check_mx", _enabled_mx),
    CheckSpec("MX", "check_mx_optional", _enabled_mx_optional),
    CheckSpec("MX", "check_mx_deprecated", _enabled_mx_deprecated),
    CheckSpec("MX", "check_mx_forbidden", _enabled_mx_forbidden),
    CheckSpec("SPF", "check_spf", _enabled_spf),
    CheckSpec("DKIM", "check_dkim", _enabled_dkim),
    CheckSpec("A", "check_a", _enabled_a),
    CheckSpec("A", "check_a_optional", _enabled_a_optional),
    CheckSpec("A", "check_a_deprecated", _enabled_a_deprecated),
    CheckSpec("A", "check_a_forbidden", _enabled_a_forbidden),
    CheckSpec("AAAA", "check_aaaa", _enabled_aaaa),
    CheckSpec("AAAA", "check_aaaa_optional", _enabled_aaaa_optional),
    CheckSpec("AAAA", "check_aaaa_deprecated", _enabled_aaaa_deprecated),
    CheckSpec("AAAA", "check_aaaa_forbidden", _enabled_aaaa_forbidden),
    CheckSpec("PTR", "check_ptr", _enabled_ptr),
    CheckSpec("PTR", "check_ptr_optional", _enabled_ptr_optional),
    CheckSpec("PTR", "check_ptr_deprecated", _enabled_ptr_deprecated),
    CheckSpec("PTR", "check_ptr_forbidden", _enabled_ptr_forbidden),
    CheckSpec("CNAME", "check_cname", _enabled_cname),
    CheckSpec("CNAME", "check_cname_optional", _enabled_cname_optional),
    CheckSpec("CNAME", "check_cname_deprecated", _enabled_cname_deprecated),
    CheckSpec("CNAME", "check_cname_forbidden", _enabled_cname_forbidden),
    CheckSpec("CAA", "check_caa", _enabled_caa),
    CheckSpec("CAA", "check_caa_optional", _enabled_caa_optional),
    CheckSpec("CAA", "check_caa_deprecated", _enabled_caa_deprecated),
    CheckSpec("CAA", "check_caa_forbidden", _enabled_caa_forbidden),
    CheckSpec("SRV", "check_srv", _enabled_srv),
    CheckSpec("SRV", "check_srv_optional", _enabled_srv_optional),
    CheckSpec("SRV", "check_srv_deprecated", _enabled_srv_deprecated),
    CheckSpec("SRV", "check_srv_forbidden", _enabled_srv_forbidden),
    CheckSpec("TLSA", "check_tlsa", _enabled_tlsa),
    CheckSpec("TLSA", "check_tlsa_optional", _enabled_tlsa_optional),
    CheckSpec("TLSA", "check_tlsa_deprecated", _enabled_tlsa_deprecated),
    CheckSpec("TLSA", "check_tlsa_forbidden", _enabled_tlsa_forbidden),
    CheckSpec("TXT", "check_txt", _enabled_txt),
    CheckSpec("TXT", "check_txt_optional", _enabled_txt_optional),
    CheckSpec("TXT", "check_txt_deprecated", _enabled_txt_deprecated),
    CheckSpec("TXT", "check_txt_forbidden", _enabled_txt_forbidden),
    CheckSpec("DMARC", "check_dmarc", _enabled_dmarc),
)

RECORD_TYPE_SPECS: tuple[RecordTypeSpec, ...] = (
    RecordTypeSpec("MX", weight=5, core=True, row_builder_name="_build_mx_rows"),
    RecordTypeSpec("SPF", weight=4, core=True, row_builder_name="_build_spf_rows"),
    RecordTypeSpec("DKIM", weight=4, core=True, row_builder_name="_build_dkim_rows"),
    RecordTypeSpec("A", weight=1, core=True, row_builder_name="_build_address_rows"),
    RecordTypeSpec("AAAA", weight=1, core=True, row_builder_name="_build_address_rows"),
    RecordTypeSpec("PTR", weight=1, core=False, row_builder_name="_build_address_rows"),
    RecordTypeSpec("CNAME", weight=3, core=True, row_builder_name="_build_cname_rows"),
    RecordTypeSpec("SRV", weight=2, core=True, row_builder_name="_build_srv_rows"),
    RecordTypeSpec("CAA", weight=1, core=False, row_builder_name="_build_caa_rows"),
    RecordTypeSpec("TLSA", weight=1, core=False, row_builder_name="_build_tlsa_rows"),
    RecordTypeSpec("TXT", weight=1, core=False, row_builder_name="_build_txt_rows"),
    RecordTypeSpec("DMARC", weight=1, core=False, row_builder_name="_build_dmarc_rows"),
)

TYPE_WEIGHTS = {spec.record_type: spec.weight for spec in RECORD_TYPE_SPECS}
CORE_RECORD_TYPES = {spec.record_type for spec in RECORD_TYPE_SPECS if spec.core}
ROW_BUILDER_NAMES = {spec.record_type: spec.row_builder_name for spec in RECORD_TYPE_SPECS}

__all__ = [
    "CHECK_SPECS",
    "CORE_RECORD_TYPES",
    "ROW_BUILDER_NAMES",
    "TYPE_WEIGHTS",
    "CheckSpec",
    "RecordTypeSpec",
]
