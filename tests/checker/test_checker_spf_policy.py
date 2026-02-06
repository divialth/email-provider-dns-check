import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.status import Status

from tests.checker.spf_support import make_provider_with_spf, make_spf_config
from tests.support import BASE_PROVIDER, FakeResolver


def test_spf_warn_on_extra_include_standard_mode():
    domain = "example.org"
    resolver = FakeResolver(
        mx={domain: ["mx1.dummy.test.", "mx2.dummy.test."]},
        txt={
            domain: ["v=spf1 include:dummy.test include:example.net -all"],
            f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:postmaster@example.org"],
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

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.WARN
    assert "extras" in spf_result.details


def test_spf_policy_softfail():
    domain = "soft.example"
    resolver = FakeResolver(
        mx={domain: ["mx1.dummy.test.", "mx2.dummy.test."]},
        txt={
            domain: ["v=spf1 include:dummy.test ~all"],
            f"_dmarc.{domain}": ["v=DMARC1;p=quarantine;rua=mailto:postmaster@soft.example"],
        },
        cname={
            f"DUMMY1._domainkey.{domain}": "DUMMY1._domainkey.dummy.test.",
            f"DUMMY2._domainkey.{domain}": "DUMMY2._domainkey.dummy.test.",
            f"DUMMY3._domainkey.{domain}": "DUMMY3._domainkey.dummy.test.",
            f"DUMMY4._domainkey.{domain}": "DUMMY4._domainkey.dummy.test.",
        },
    )

    checker = DNSChecker(
        domain,
        BASE_PROVIDER,
        resolver=resolver,
        strict=False,
        spf_policy="softfail",
        dmarc_policy="quarantine",
    )
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_policy_not_last_passes():
    domain = "soft.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 ~all include:dummy.test"],
        }
    )

    checker = DNSChecker(
        domain,
        BASE_PROVIDER,
        resolver=resolver,
        strict=False,
        spf_policy="softfail",
    )
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_strict_uses_strict_record():
    provider = make_provider_with_spf(
        make_spf_config(
            required_record="v=spf1 include:strict.example -all",
            includes=["strict.example"],
        ),
        provider_id="spf_strict",
        name="Strict SPF Provider",
    )
    domain = "strict.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 include:strict.example -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=True, spf_policy="softfail")
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_strict_mismatch_fails():
    provider = make_provider_with_spf(
        make_spf_config(
            required_record="v=spf1 include:strict.example -all",
            includes=["strict.example"],
        ),
        provider_id="spf_strict",
        name="Strict SPF Provider",
    )
    domain = "strict.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 include:strict.example ~all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=True)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL


def test_spf_multiple_records_fail():
    provider = make_provider_with_spf(
        make_spf_config(
            required_record="v=spf1 include:multi.example -all",
            includes=["multi.example"],
        ),
        provider_id="spf_multi",
        name="Multiple SPF Provider",
    )
    domain = "multi.example"
    resolver = FakeResolver(
        txt={
            domain: [
                "v=spf1 include:multi.example -all",
                "v=spf1 include:extra.example -all",
            ],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL


def test_spf_dns_failure_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, domain: str):
            raise DnsLookupError("TXT", domain, RuntimeError("timeout"))

    provider = make_provider_with_spf(
        make_spf_config(
            required_record="v=spf1 include:dummy.test -all",
            includes=["dummy.test"],
        ),
        provider_id="spf_fail",
        name="SPF Fail Provider",
    )
    domain = "fail.example"
    resolver = FailingResolver()

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.UNKNOWN


def test_spf_requires_config():
    provider = make_provider_with_spf(
        None,
        provider_id="spf_none",
        name="No SPF Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_spf()


def test_build_expected_spf_requires_config():
    provider = make_provider_with_spf(
        None,
        provider_id="spf_none",
        name="No SPF Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker._build_expected_spf()


def test_spf_no_records_fails():
    provider = make_provider_with_spf(
        make_spf_config(
            includes=["example.test"],
        ),
        provider_id="spf_missing",
        name="Missing SPF Provider",
    )
    resolver = FakeResolver(txt={"example.test": ["not-spf"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL
