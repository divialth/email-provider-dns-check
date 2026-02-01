import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import DMARCConfig, ProviderConfig

from tests.support import BASE_PROVIDER, FakeResolver


def test_dmarc_warn_on_unexpected_rua():
    domain = "example.net"
    resolver = FakeResolver(
        mx={domain: ["mx1.dummy.test.", "mx2.dummy.test."]},
        txt={
            domain: ["v=spf1 include:dummy.test -all"],
            f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:different@example.net"],
        },
        cname={
            f"DUMMY1._domainkey.{domain}": "DUMMY1._domainkey.dummy.test.",
            f"DUMMY2._domainkey.{domain}": "DUMMY2._domainkey.dummy.test.",
            f"DUMMY3._domainkey.{domain}": "DUMMY3._domainkey.dummy.test.",
            f"DUMMY4._domainkey.{domain}": "DUMMY4._domainkey.dummy.test.",
        },
    )

    checker = DNSChecker(domain, BASE_PROVIDER, resolver=resolver, strict=False)
    results = checker.run_checks()
    dmarc_result = next(r for r in results if r.record_type == "DMARC")

    assert dmarc_result.status == "WARN"
    assert "expected_rua" in dmarc_result.details


def test_dmarc_required_rua_and_tags():
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            default_rua_localpart="postmaster",
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s", "aspf": "s"},
        ),
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:agg@example.test;adkim=s;aspf=s"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dmarc_result = next(r for r in results if r.record_type == "DMARC")
    assert dmarc_result.status == "PASS"


def test_dmarc_missing_required_rua_fails():
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            default_rua_localpart="postmaster",
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s"},
        ),
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:other@example.test;adkim=s"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dmarc_result = next(r for r in results if r.record_type == "DMARC")
    assert dmarc_result.status == "FAIL"


def test_dmarc_requires_config():
    provider = ProviderConfig(
        provider_id="dmarc_none",
        name="No DMARC Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_dmarc()


def test_dmarc_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, domain: str):
            raise DnsLookupError("TXT", domain, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            default_rua_localpart="postmaster",
            required_rua=[],
            required_tags={},
        ),
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_dmarc()

    assert result.status == "UNKNOWN"


def test_dmarc_strict_mismatch_fails():
    provider = ProviderConfig(
        provider_id="dmarc_strict",
        name="DMARC Strict Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            default_rua_localpart="postmaster",
            required_rua=[],
            required_tags={},
        ),
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=none;rua=mailto:x"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status == "FAIL"


def test_dmarc_records_missing_requirements_fail():
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            default_rua_localpart="postmaster",
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s"},
        ),
    )
    resolver = FakeResolver(
        txt={
            "_dmarc.example.test": [
                "v=DMARC2;p=reject;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=none;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=reject",
                "v=DMARC1;p=reject;rua=mailto:agg@example.test",
            ]
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status == "FAIL"
