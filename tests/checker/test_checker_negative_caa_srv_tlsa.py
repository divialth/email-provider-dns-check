"""Tests for deprecated/forbidden CAA, SRV, and TLSA checks."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import (
    CAAMatchRule,
    CAAConfig,
    CAARecord,
    ProviderConfig,
    SRVConfig,
    SRVMatchRule,
    SRVRecord,
    TLSAConfig,
    TLSAMatchRule,
    TLSARecord,
)
from provider_check.status import Status

from tests.support import FakeResolver


def _provider(
    *,
    caa: CAAConfig | None = None,
    srv: SRVConfig | None = None,
    tlsa: TLSAConfig | None = None,
) -> ProviderConfig:
    return ProviderConfig(
        provider_id="negative-caa-srv-tlsa",
        name="Negative CAA SRV TLSA",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        caa=caa,
        srv=srv,
        tlsa=tlsa,
        txt=None,
        dmarc=None,
    )


def test_caa_negative_checks() -> None:
    provider = _provider(
        caa=CAAConfig(
            required={},
            deprecated={
                "@": CAAMatchRule(
                    match="exact",
                    entries=[CAARecord(flags=0, tag="issue", value="legacy.example")],
                )
            },
            forbidden={"@": CAAMatchRule(match="any", entries=[])},
        )
    )
    resolver = FakeResolver(caa={"example.com": [(0, "issue", "legacy.example")]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_caa_deprecated()
    forbidden_result = checker.check_caa_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_caa_forbidden_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_caa(self, name: str):
            raise DnsLookupError("CAA", name, RuntimeError("timeout"))

    provider = _provider(
        caa=CAAConfig(required={}, forbidden={"@": CAAMatchRule(match="any", entries=[])})
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_caa_forbidden()

    assert result.status is Status.UNKNOWN
    assert result.scope == "forbidden"


def test_caa_deprecated_no_rules_passes() -> None:
    provider = _provider(caa=CAAConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_caa_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_caa_forbidden_passes_without_matches() -> None:
    provider = _provider(
        caa=CAAConfig(
            required={},
            forbidden={
                "@": CAAMatchRule(
                    match="exact",
                    entries=[CAARecord(flags=0, tag="issue", value="blocked.example")],
                )
            },
        )
    )
    resolver = FakeResolver(caa={"example.com": [(0, "issue", "safe.example")]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_caa_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_caa_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(caa=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="CAA configuration not available"):
        checker.check_caa_deprecated()
    with pytest.raises(ValueError, match="CAA configuration not available"):
        checker.check_caa_forbidden()


def test_srv_negative_checks() -> None:
    provider = _provider(
        srv=SRVConfig(
            required={},
            deprecated={
                "_sip._tls": SRVMatchRule(
                    match="exact",
                    entries=[
                        SRVRecord(priority=100, weight=1, port=443, target="srv.example.test.")
                    ],
                )
            },
            forbidden={"_sip._tcp": SRVMatchRule(match="any", entries=[])},
        )
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "srv.example.test.")],
            "_sip._tcp.example.com": [(10, 1, 443, "blocked.example.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_srv_deprecated()
    forbidden_result = checker.check_srv_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_srv_negative_passes_without_matches() -> None:
    provider = _provider(
        srv=SRVConfig(
            required={},
            forbidden={
                "_sip._tcp": SRVMatchRule(
                    match="exact",
                    entries=[
                        SRVRecord(priority=10, weight=1, port=443, target="blocked.example.test.")
                    ],
                )
            },
        )
    )
    resolver = FakeResolver(srv={"_sip._tcp.example.com": [(20, 1, 443, "safe.example.test.")]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_srv_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_srv_deprecated_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_srv(self, name: str):
            raise DnsLookupError("SRV", name, RuntimeError("timeout"))

    provider = _provider(
        srv=SRVConfig(required={}, deprecated={"_sip._tls": SRVMatchRule(match="any", entries=[])})
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_srv_deprecated()

    assert result.status is Status.UNKNOWN
    assert result.scope == "deprecated"


def test_srv_deprecated_no_rules_passes() -> None:
    provider = _provider(srv=SRVConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_srv_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_srv_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(srv=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="SRV configuration not available"):
        checker.check_srv_deprecated()
    with pytest.raises(ValueError, match="SRV configuration not available"):
        checker.check_srv_forbidden()


def test_tlsa_negative_checks() -> None:
    provider = _provider(
        tlsa=TLSAConfig(
            required={},
            deprecated={
                "_25._tcp.mail": TLSAMatchRule(
                    match="exact",
                    entries=[
                        TLSARecord(
                            usage=3,
                            selector=1,
                            matching_type=1,
                            certificate_association="abc123",
                        )
                    ],
                )
            },
            forbidden={"_443._tcp.mail": TLSAMatchRule(match="any", entries=[])},
        )
    )
    resolver = FakeResolver(
        tlsa={
            "_25._tcp.mail.example.com": [(3, 1, 1, "abc123")],
            "_443._tcp.mail.example.com": [(3, 1, 1, "def456")],
        },
        tlsa_dnssec={"_25._tcp.mail.example.com": True, "_443._tcp.mail.example.com": False},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_tlsa_deprecated()
    forbidden_result = checker.check_tlsa_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"
    assert forbidden_result.details["dnssec_status"]["_443._tcp.mail.example.com"] is False


def test_tlsa_forbidden_passes_without_matches() -> None:
    provider = _provider(
        tlsa=TLSAConfig(
            required={},
            forbidden={
                "_443._tcp.mail": TLSAMatchRule(
                    match="exact",
                    entries=[
                        TLSARecord(
                            usage=3,
                            selector=1,
                            matching_type=1,
                            certificate_association="blocked",
                        )
                    ],
                )
            },
        )
    )
    resolver = FakeResolver(tlsa={"_443._tcp.mail.example.com": [(3, 1, 1, "safe")]})

    result = DNSChecker("example.com", provider, resolver=resolver).check_tlsa_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_tlsa_deprecated_no_rules_passes() -> None:
    provider = _provider(tlsa=TLSAConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_tlsa_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_tlsa_negative_uses_get_tlsa_when_status_method_missing() -> None:
    class NoStatusResolver:
        def get_tlsa(self, name: str):
            return [(3, 1, 1, "abc123")]

    provider = _provider(
        tlsa=TLSAConfig(
            required={},
            deprecated={"_25._tcp.mail": TLSAMatchRule(match="any", entries=[])},
        )
    )

    result = DNSChecker(
        "example.com", provider, resolver=NoStatusResolver()
    ).check_tlsa_deprecated()

    assert result.status is Status.WARN
    assert result.scope == "deprecated"
    assert result.details["dnssec_status"]["_25._tcp.mail.example.com"] is None


def test_tlsa_deprecated_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_tlsa_with_status(self, name: str):
            raise DnsLookupError("TLSA", name, RuntimeError("timeout"))

    provider = _provider(
        tlsa=TLSAConfig(
            required={},
            deprecated={"_25._tcp.mail": TLSAMatchRule(match="any", entries=[])},
        )
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_tlsa_deprecated()

    assert result.status is Status.UNKNOWN
    assert result.scope == "deprecated"


def test_tlsa_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(tlsa=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="TLSA configuration not available"):
        checker.check_tlsa_deprecated()
    with pytest.raises(ValueError, match="TLSA configuration not available"):
        checker.check_tlsa_forbidden()
