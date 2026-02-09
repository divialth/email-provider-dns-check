"""Tests for deprecated/forbidden MX checks."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.provider_config import MXNegativePolicy, MXNegativeRules, MXRecord
from provider_check.status import Status

from tests.checker.mx_support import make_mx_config, make_provider_with_mx
from tests.support import FakeResolver


def test_mx_deprecated_exact_match_warns() -> None:
    provider = make_provider_with_mx(
        make_mx_config(
            deprecated=MXNegativeRules(
                policy=MXNegativePolicy(match="exact"),
                entries=[MXRecord(host="legacy.example.test.", priority=5)],
            )
        )
    )
    resolver = FakeResolver(mx={"example.test": [("legacy.example.test.", 5)]})

    result = DNSChecker("example.test", provider, resolver=resolver).check_mx_deprecated()

    assert result.status is Status.WARN
    assert result.scope == "deprecated"
    assert result.details["matched"] == ["legacy.example.test."]
    assert result.details["policy"]["match"] == "exact"


def test_mx_deprecated_exact_priority_mismatch_passes() -> None:
    provider = make_provider_with_mx(
        make_mx_config(
            deprecated=MXNegativeRules(
                policy=MXNegativePolicy(match="exact"),
                entries=[MXRecord(host="legacy.example.test.", priority=5)],
            )
        )
    )
    resolver = FakeResolver(mx={"example.test": [("legacy.example.test.", 10)]})

    result = DNSChecker("example.test", provider, resolver=resolver).check_mx_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"
    assert result.details["matched"] == []


def test_mx_deprecated_exact_missing_host_passes() -> None:
    provider = make_provider_with_mx(
        make_mx_config(
            deprecated=MXNegativeRules(
                policy=MXNegativePolicy(match="exact"),
                entries=[MXRecord(host="legacy.example.test.", priority=5)],
            )
        )
    )
    resolver = FakeResolver(mx={"example.test": [("other.example.test.", 10)]})

    result = DNSChecker("example.test", provider, resolver=resolver).check_mx_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"
    assert result.details["matched"] == []


def test_mx_forbidden_exact_host_without_priority_fails() -> None:
    provider = make_provider_with_mx(
        make_mx_config(
            forbidden=MXNegativeRules(
                policy=MXNegativePolicy(match="exact"),
                entries=[MXRecord(host="legacy.example.test.")],
            )
        )
    )
    resolver = FakeResolver(mx={"example.test": [("legacy.example.test.", 50)]})

    result = DNSChecker("example.test", provider, resolver=resolver).check_mx_forbidden()

    assert result.status is Status.FAIL
    assert result.scope == "forbidden"
    assert result.details["matched"] == ["legacy.example.test."]


def test_mx_forbidden_any_match_fails() -> None:
    provider = make_provider_with_mx(
        make_mx_config(forbidden=MXNegativeRules(policy=MXNegativePolicy(match="any")))
    )
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})

    result = DNSChecker("example.test", provider, resolver=resolver).check_mx_forbidden()

    assert result.status is Status.FAIL
    assert result.scope == "forbidden"
    assert result.details["policy"]["match"] == "any"
    assert result.details["matched"] == ["mx1.example.test."]


def test_mx_forbidden_any_passes_without_mx_records() -> None:
    provider = make_provider_with_mx(
        make_mx_config(forbidden=MXNegativeRules(policy=MXNegativePolicy(match="any")))
    )

    result = DNSChecker("example.test", provider, resolver=FakeResolver()).check_mx_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"
    assert result.details["matched"] == []


def test_mx_deprecated_no_rules_passes() -> None:
    provider = make_provider_with_mx(make_mx_config())

    result = DNSChecker("example.test", provider, resolver=FakeResolver()).check_mx_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"
    assert result.message == "No deprecated MX records configured"


def test_mx_negative_checks_require_mx_config() -> None:
    checker = DNSChecker("example.test", make_provider_with_mx(None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="MX configuration not available"):
        checker.check_mx_deprecated()
    with pytest.raises(ValueError, match="MX configuration not available"):
        checker.check_mx_forbidden()
