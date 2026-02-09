"""Optional TLSA checker tests."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import TLSARecord
from provider_check.status import Status

from tests.checker.tlsa_support import make_provider_with_tlsa, make_tlsa_config
from tests.support import FakeResolver

OPTIONAL_AUTODISCOVER = {
    "_443._tcp.autodiscover": [
        TLSARecord(
            usage=3,
            selector=1,
            matching_type=1,
            certificate_association="ddeeff",
        )
    ]
}


def test_tlsa_optional_missing_warns() -> None:
    """Warn when optional TLSA records are missing."""
    provider = make_provider_with_tlsa(
        make_tlsa_config(
            required={
                "_25._tcp.mail": [
                    TLSARecord(
                        usage=3,
                        selector=1,
                        matching_type=1,
                        certificate_association="aabbcc",
                    )
                ]
            },
            optional=OPTIONAL_AUTODISCOVER,
        )
    )
    resolver = FakeResolver(
        tlsa={"_25._tcp.mail.example.com": [(3, 1, 1, "aabbcc")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa_optional()

    assert result.status is Status.WARN
    assert result.message == "TLSA optional records missing"
    assert result.optional is True


def test_tlsa_optional_present_passes() -> None:
    """Pass when optional TLSA records are present."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "DDEEFF")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa_optional()

    assert result.status is Status.PASS
    assert result.message == "TLSA optional records present"
    assert result.optional is True


def test_tlsa_optional_mismatch_fails() -> None:
    """Fail when optional TLSA records are present but mismatched."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "wrong")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa_optional()

    assert result.status is Status.FAIL
    assert result.message == "TLSA optional records mismatched"
    assert result.optional is True


def test_tlsa_optional_no_records_passes() -> None:
    """Pass when no optional TLSA records are configured."""
    provider = make_provider_with_tlsa(
        make_tlsa_config(
            required={
                "_25._tcp.mail": [
                    TLSARecord(
                        usage=3,
                        selector=1,
                        matching_type=1,
                        certificate_association="aabbcc",
                    )
                ]
            }
        )
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_tlsa_optional()

    assert result.status is Status.PASS
    assert result.message == "No optional TLSA records required"
    assert result.optional is True


def test_tlsa_optional_requires_config() -> None:
    """Raise when provider has no TLSA config."""
    provider = make_provider_with_tlsa(
        None,
        provider_id="no_tlsa",
        name="No TLSA Provider",
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="TLSA configuration not available for provider"):
        checker.check_tlsa_optional()


def test_tlsa_optional_dns_lookup_error_returns_unknown() -> None:
    """Return UNKNOWN when optional TLSA lookup fails."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))

    class ErrorResolver:
        """Resolver that raises lookup errors."""

        def get_tlsa(self, name: str):
            """Raise a TLSA lookup error."""
            raise DnsLookupError("TLSA", name, RuntimeError("boom"))

    checker = DNSChecker("example.com", provider, resolver=ErrorResolver())

    result = checker.check_tlsa_optional()

    assert result.status is Status.UNKNOWN


def test_tlsa_optional_fails_when_dnssec_not_authenticated() -> None:
    """Fail optional TLSA checks when answers are not DNSSEC-authenticated."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
        tlsa_dnssec={"_443._tcp.autodiscover.example.com": False},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_tlsa_optional()

    assert result.status is Status.FAIL
    assert result.message == "TLSA optional records are not DNSSEC-authenticated"


def test_tlsa_optional_unknown_when_live_verification_errors(monkeypatch) -> None:
    """Return UNKNOWN when live TLS verification encounters endpoint errors."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
        tlsa_dnssec={"_443._tcp.autodiscover.example.com": True},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    monkeypatch.setattr(
        checker,
        "_verify_tlsa_bindings",
        lambda _records: {
            "unsupported_names": {},
            "unsupported_entries": {},
            "endpoint_errors": {"_443._tcp.autodiscover.example.com": "connection failed"},
            "pkix_failures": {},
            "certificate_mismatches": {},
        },
    )

    result = checker.check_tlsa_optional()

    assert result.status is Status.UNKNOWN
    assert result.message == "TLSA certificate verification failed"


def test_tlsa_optional_fails_when_dane_settings_are_unsupported(monkeypatch) -> None:
    """Fail optional TLSA checks when DANE verification settings are unsupported."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
        tlsa_dnssec={"_443._tcp.autodiscover.example.com": True},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    monkeypatch.setattr(
        checker,
        "_verify_tlsa_bindings",
        lambda _records: {
            "unsupported_names": {"_443._tcp.autodiscover.example.com": "unsupported"},
            "unsupported_entries": {},
            "endpoint_errors": {},
            "pkix_failures": {},
            "certificate_mismatches": {},
        },
    )

    result = checker.check_tlsa_optional()

    assert result.status is Status.FAIL
    assert result.message == "TLSA optional records use unsupported DANE settings"


def test_tlsa_optional_fails_when_dane_binding_mismatches(monkeypatch) -> None:
    """Fail optional TLSA checks when certificate bindings do not match."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))

    class LiveResolver(FakeResolver):
        """Fake resolver that enables live verification flow."""

        supports_live_tls_verification = True

    resolver = LiveResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
        tlsa_dnssec={"_443._tcp.autodiscover.example.com": True},
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
            "certificate_mismatches": {"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
        },
    )

    result = checker.check_tlsa_optional()

    assert result.status is Status.FAIL
    assert result.message == "TLSA optional records do not match presented TLS certificates"


def test_run_checks_includes_optional_tlsa() -> None:
    """Include optional TLSA checks in run_checks results when configured."""
    provider = make_provider_with_tlsa(make_tlsa_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        tlsa={"_443._tcp.autodiscover.example.com": [(3, 1, 1, "ddeeff")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "TLSA" and result.optional for result in results)
