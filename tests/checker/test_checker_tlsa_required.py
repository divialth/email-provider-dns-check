"""Required TLSA checker tests."""

from __future__ import annotations

import hashlib

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


def test_tlsa_fails_when_dnssec_not_authenticated() -> None:
    """Fail when TLSA answers are present without DNSSEC authentication."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
        tlsa_dnssec={"_25._tcp.mail.example.com": False},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA records are not DNSSEC-authenticated"


def test_tlsa_fails_when_dane_binding_mismatches(monkeypatch) -> None:
    """Fail when live TLS certificates do not satisfy TLSA bindings."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
        tlsa_dnssec={"_25._tcp.mail.example.com": True},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    monkeypatch.setattr(
        checker,
        "_verify_tlsa_bindings",
        lambda _records: {
            "unsupported_names": {},
            "unsupported_entries": {},
            "endpoint_errors": {},
            "pkix_failures": {},
            "certificate_mismatches": {"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
        },
    )

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA records do not match presented TLS certificates"


def test_tlsa_unknown_when_live_verification_errors(monkeypatch) -> None:
    """Return UNKNOWN when live TLS verification encounters endpoint errors."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
        tlsa_dnssec={"_25._tcp.mail.example.com": True},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    monkeypatch.setattr(
        checker,
        "_verify_tlsa_bindings",
        lambda _records: {
            "unsupported_names": {},
            "unsupported_entries": {},
            "endpoint_errors": {"_25._tcp.mail.example.com": "connection failed"},
            "pkix_failures": {},
            "certificate_mismatches": {},
        },
    )

    result = checker.check_tlsa()

    assert result.status is Status.UNKNOWN
    assert result.message == "TLSA certificate verification failed"


def test_tlsa_fails_when_dane_settings_are_unsupported(monkeypatch) -> None:
    """Fail when TLSA names/settings cannot be verified with DANE semantics."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
        tlsa_dnssec={"_25._tcp.mail.example.com": True},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    monkeypatch.setattr(
        checker,
        "_verify_tlsa_bindings",
        lambda _records: {
            "unsupported_names": {"_25._tcp.mail.example.com": "unsupported"},
            "unsupported_entries": {},
            "endpoint_errors": {},
            "pkix_failures": {},
            "certificate_mismatches": {},
        },
    )

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA DANE verification unsupported for one or more records"


def test_tlsa_without_dnssec_status_fails() -> None:
    """Fail when resolver cannot report DNSSEC status for TLSA answers."""

    class LegacyResolver:
        """Resolver that only supports legacy TLSA lookups."""

        supports_live_tls_verification = False

        def get_tlsa(self, name: str):
            """Return a legacy TLSA answer list."""
            assert name == "_25._tcp.mail.example.com"
            return [(3, 1, 1, "aabbcc")]

    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    checker = DNSChecker("example.com", provider, resolver=LegacyResolver())

    result = checker.check_tlsa()

    assert result.status is Status.FAIL
    assert result.message == "TLSA records are not DNSSEC-authenticated"


def test_tlsa_internal_helpers_cover_selector_and_matching_paths(monkeypatch) -> None:
    """Exercise selector and matching helper branches."""
    provider = make_provider_with_tlsa(make_tlsa_config(required=PRIMARY_REQUIRED))
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    assert checker._parse_tlsa_owner_name("_25._tcp.mail.example.com") == (
        25,
        "tcp",
        "mail.example.com",
    )
    assert checker._parse_tlsa_owner_name("invalid") is None
    assert checker._parse_tlsa_owner_name("_25.mail.example.com") is None
    assert checker._parse_tlsa_owner_name("_xx._tcp.mail.example.com") is None
    assert checker._parse_tlsa_owner_name("_25._tcp.") is None
    assert checker._parse_tlsa_owner_name("_25._tcp. ") is None
    assert checker._dnssec_unverified_names({"a": True, "b": False, "c": None}) == ["b", "c"]
    assert isinstance(checker._has_cryptography(), bool)
    assert isinstance(checker._has_pyopenssl(), bool)
    assert checker._should_run_live_tlsa_verification() is False

    cert = b"\xaa\xbb\xcc"
    cache = {}
    assert checker._tlsa_selector_bytes(cert, 0, cache) == cert

    monkeypatch.setattr(checker, "_extract_spki_der", lambda _cert: b"\x01\x02")
    assert checker._tlsa_selector_bytes(cert, 1, cache) == b"\x01\x02"
    assert checker._tlsa_selector_bytes(cert, 1, cache) == b"\x01\x02"

    dispatch_checker = DNSChecker("example.com", provider, resolver=FakeResolver())
    monkeypatch.setattr(dispatch_checker, "_has_cryptography", lambda: True)
    monkeypatch.setattr(
        dispatch_checker, "_extract_spki_der_with_cryptography", lambda _cert: b"\x03\x04"
    )
    monkeypatch.setattr(
        dispatch_checker, "_extract_spki_der_with_openssl", lambda _cert: b"\x05\x06"
    )
    assert dispatch_checker._extract_spki_der(cert) == b"\x03\x04"
    monkeypatch.setattr(dispatch_checker, "_has_cryptography", lambda: False)
    assert dispatch_checker._extract_spki_der(cert) == b"\x05\x06"

    with pytest.raises(ValueError, match="Unsupported TLSA selector"):
        checker._tlsa_selector_bytes(cert, 9, cache)

    assert checker._tlsa_entry_matches_certificate((3, 0, 0, cert.hex()), cert, cache) is True
    assert (
        checker._tlsa_entry_matches_certificate(
            (3, 0, 1, hashlib.sha256(cert).hexdigest()), cert, cache
        )
        is True
    )
    assert (
        checker._tlsa_entry_matches_certificate(
            (3, 0, 2, hashlib.sha512(cert).hexdigest()), cert, cache
        )
        is True
    )
    with pytest.raises(ValueError, match="Unsupported TLSA matching_type"):
        checker._tlsa_entry_matches_certificate((3, 0, 9, "deadbeef"), cert, cache)


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
