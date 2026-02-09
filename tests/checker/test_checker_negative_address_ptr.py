"""Tests for deprecated/forbidden A/AAAA/PTR checks."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import AddressConfig, PTRConfig, ProviderConfig, ValuesMatchRule
from provider_check.status import Status

from tests.support import FakeResolver


def _provider(*, a: AddressConfig | None = None, aaaa: AddressConfig | None = None, ptr=None):
    return ProviderConfig(
        provider_id="negative-address",
        name="Negative Address",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        a=a,
        aaaa=aaaa,
        ptr=ptr,
        txt=None,
        dmarc=None,
    )


def test_a_deprecated_exact_match_warns() -> None:
    provider = _provider(
        a=AddressConfig(
            required={},
            deprecated={"legacy": ValuesMatchRule(match="exact", values=["192.0.2.9"])},
        )
    )
    resolver = FakeResolver(a={"legacy.example.com": ["192.0.2.9"]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_a_deprecated()

    assert result.status is Status.WARN
    assert result.scope == "deprecated"
    assert "legacy.example.com" in result.details["matched"]


def test_a_forbidden_any_match_fails() -> None:
    provider = _provider(
        a=AddressConfig(
            required={},
            forbidden={"blocked": ValuesMatchRule(match="any", values=[])},
        )
    )
    resolver = FakeResolver(a={"blocked.example.com": ["203.0.113.10"]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_a_forbidden()

    assert result.status is Status.FAIL
    assert result.scope == "forbidden"


def test_a_forbidden_passes_without_matches() -> None:
    provider = _provider(
        a=AddressConfig(
            required={},
            forbidden={"blocked": ValuesMatchRule(match="exact", values=["203.0.113.10"])},
        )
    )
    resolver = FakeResolver(a={"blocked.example.com": ["203.0.113.20"]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_a_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_a_deprecated_no_rules_passes() -> None:
    provider = _provider(a=AddressConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_a_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_a_forbidden_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_a(self, name: str):
            raise DnsLookupError("A", name, RuntimeError("timeout"))

    provider = _provider(
        a=AddressConfig(
            required={},
            forbidden={"blocked": ValuesMatchRule(match="any", values=[])},
        )
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_a_forbidden()

    assert result.status is Status.UNKNOWN
    assert result.scope == "forbidden"


def test_a_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(a=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="A configuration not available"):
        checker.check_a_deprecated()
    with pytest.raises(ValueError, match="A configuration not available"):
        checker.check_a_forbidden()


def test_aaaa_negative_checks() -> None:
    provider = _provider(
        aaaa=AddressConfig(
            required={},
            deprecated={"legacy6": ValuesMatchRule(match="exact", values=["2001:db8::9"])},
            forbidden={"blocked6": ValuesMatchRule(match="any", values=[])},
        )
    )
    resolver = FakeResolver(
        aaaa={
            "legacy6.example.com": ["2001:db8::9"],
            "blocked6.example.com": ["2001:db8::99"],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_aaaa_deprecated()
    forbidden_result = checker.check_aaaa_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_aaaa_forbidden_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_aaaa(self, name: str):
            raise DnsLookupError("AAAA", name, RuntimeError("timeout"))

    provider = _provider(
        aaaa=AddressConfig(
            required={},
            forbidden={"blocked6": ValuesMatchRule(match="any", values=[])},
        )
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_aaaa_forbidden()

    assert result.status is Status.UNKNOWN
    assert result.scope == "forbidden"


def test_aaaa_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(aaaa=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="AAAA configuration not available"):
        checker.check_aaaa_deprecated()
    with pytest.raises(ValueError, match="AAAA configuration not available"):
        checker.check_aaaa_forbidden()


def test_ptr_negative_checks() -> None:
    provider = _provider(
        ptr=PTRConfig(
            required={},
            deprecated={
                "10.2.0.192.in-addr.arpa.": ValuesMatchRule(
                    match="exact",
                    values=["legacy.example.test."],
                )
            },
            forbidden={"11.2.0.192.in-addr.arpa.": ValuesMatchRule(match="any", values=[])},
        )
    )
    resolver = FakeResolver(
        ptr={
            "10.2.0.192.in-addr.arpa": ["legacy.example.test."],
            "11.2.0.192.in-addr.arpa": ["blocked.example.test."],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_ptr_deprecated()
    forbidden_result = checker.check_ptr_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_ptr_forbidden_passes_without_rules() -> None:
    provider = _provider(ptr=PTRConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_ptr_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_ptr_forbidden_passes_without_matches() -> None:
    provider = _provider(
        ptr=PTRConfig(
            required={},
            forbidden={
                "11.2.0.192.in-addr.arpa.": ValuesMatchRule(
                    match="exact",
                    values=["blocked.example.test."],
                )
            },
        )
    )
    resolver = FakeResolver(ptr={"11.2.0.192.in-addr.arpa": ["safe.example.test."]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_ptr_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_ptr_deprecated_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_ptr(self, name: str):
            raise DnsLookupError("PTR", name, RuntimeError("timeout"))

    provider = _provider(
        ptr=PTRConfig(
            required={},
            deprecated={"10.2.0.192.in-addr.arpa.": ValuesMatchRule(match="any", values=[])},
        )
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_ptr_deprecated()

    assert result.status is Status.UNKNOWN
    assert result.scope == "deprecated"


def test_ptr_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(ptr=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="PTR configuration not available"):
        checker.check_ptr_deprecated()
    with pytest.raises(ValueError, match="PTR configuration not available"):
        checker.check_ptr_forbidden()
