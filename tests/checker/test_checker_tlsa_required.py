"""Required TLSA checker tests."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import TLSARecord
from provider_check.status import Status

from tests.checker.tlsa_support import make_provider_with_tlsa, make_tlsa_config
from tests.support import FakeResolver

PRIMARY_REQUIRED = {
    "_25._tcp.mail": [
        TLSARecord(
            usage=3,
            selector=1,
            matching_type=1,
            certificate_association="AABBCC",
        )
    ]
}


def test_tlsa_passes_when_records_match() -> None:
    """Pass when required TLSA records exactly match."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa()

    assert result.status is Status.PASS
    assert result.message == "Required TLSA records present"


def test_tlsa_missing_records_fail() -> None:
    """Fail when required TLSA records are missing."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(tlsa={"_25._tcp.mail.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "Missing required TLSA records"
    assert result.details["missing"] == {"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]}


def test_tlsa_extra_records_warn_in_non_strict() -> None:
    """Warn in non-strict mode when additional TLSA records exist."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        tlsa={
            "_25._tcp.mail.example.com": [
                (3, 1, 1, "aabbcc"),
                (3, 1, 1, "ddeeff"),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_tlsa()

    assert result.status is Status.WARN
    assert result.message == "Additional TLSA records present; required records found"
    assert result.details["extra"] == {"_25._tcp.mail.example.com": [(3, 1, 1, "ddeeff")]}


def test_tlsa_extra_records_fail_in_strict() -> None:
    """Fail in strict mode when additional TLSA records exist."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        tlsa={
            "_25._tcp.mail.example.com": [
                (3, 1, 1, "aabbcc"),
                (3, 1, 1, "ddeeff"),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA records do not exactly match required configuration"


def test_tlsa_strict_passes_when_records_match() -> None:
    """Pass in strict mode when required records match exactly."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "AABBCC")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_tlsa()

    assert result.status is Status.PASS
    assert result.message == "TLSA records match required configuration"


def test_tlsa_strict_missing_records_include_missing_details() -> None:
    """Fail in strict mode and include missing details when records are absent."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(tlsa={"_25._tcp.mail.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA records do not exactly match required configuration"
    assert result.details["missing"] == {"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]}


def test_tlsa_dns_lookup_error_returns_unknown() -> None:
    """Return UNKNOWN when TLSA lookup fails."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))

    class ErrorResolver:
        """Resolver that raises lookup errors."""

        def get_tlsa(self, name: str):
            """Raise a TLSA lookup error."""
            raise DnsLookupError("TLSA", name, RuntimeError("boom"))

    checker = DNSChecker("example.com", provider, resolver=ErrorResolver())

    result = checker.check_tlsa()

    assert result.status is Status.UNKNOWN


def test_tlsa_requires_config() -> None:
    """Raise when provider has no TLSA config."""
    provider = make_provider_with_tlsa(
        None,
        provider_id="no_tlsa",
        name="No TLSA Provider",
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="TLSA configuration not available for provider"):
        checker.check_tlsa()
