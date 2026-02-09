import pytest

from provider_check.checker import RecordCheck
from provider_check.status import Status


def test_record_check_coerces_status_string() -> None:
    result = RecordCheck("MX", "PASS", "ok", {})
    assert result.status is Status.PASS


def test_record_check_scope_defaults_to_required() -> None:
    result = RecordCheck.pass_("MX", "ok", {})

    assert result.scope == "required"
    assert result.optional is False


def test_record_check_optional_sets_scope() -> None:
    result = RecordCheck.warn("MX", "optional", {}, optional=True)

    assert result.scope == "optional"
    assert result.optional is True


def test_record_check_optional_promotes_required_scope() -> None:
    result = RecordCheck("MX", "PASS", "ok", {}, optional=True, scope="required")

    assert result.scope == "optional"
    assert result.optional is True


def test_record_check_deprecated_scope_not_optional() -> None:
    result = RecordCheck.warn("MX", "deprecated", {}, scope="deprecated")

    assert result.scope == "deprecated"
    assert result.optional is False


def test_record_check_invalid_scope_rejected() -> None:
    with pytest.raises(ValueError, match="scope must be one of"):
        RecordCheck.pass_("MX", "bad", {}, scope="unsupported")
