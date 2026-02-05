import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import ProviderConfig, SPFConfig
from provider_check.status import Status

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
    provider = ProviderConfig(
        provider_id="spf_strict",
        name="Strict SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["strict.example"],
            strict_record="v=spf1 include:strict.example -all",
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
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
    provider = ProviderConfig(
        provider_id="spf_strict",
        name="Strict SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["strict.example"],
            strict_record="v=spf1 include:strict.example -all",
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
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
    provider = ProviderConfig(
        provider_id="spf_multi",
        name="Multiple SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["multi.example"],
            strict_record="v=spf1 include:multi.example -all",
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
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

    provider = ProviderConfig(
        provider_id="spf_fail",
        name="SPF Fail Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["dummy.test"],
            strict_record="v=spf1 include:dummy.test -all",
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "fail.example"
    resolver = FailingResolver()

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.UNKNOWN


def test_spf_allowed_mechanisms_pass():
    provider = ProviderConfig(
        provider_id="spf_allowed",
        name="Allowed SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=["a", "mx"],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "allowed.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a mx -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_unexpected_mechanism_warns_when_configured():
    provider = ProviderConfig(
        provider_id="spf_warn",
        name="Warn SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=["a"],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "warn.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a ptr -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.WARN
    assert "ptr" in spf_result.details.get("extras", [])


def test_spf_required_modifiers_missing_fails():
    provider = ProviderConfig(
        provider_id="spf_mod",
        name="Modifier SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={"redirect": "_spf.example.test"},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "mod.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL


def test_spf_requires_config():
    provider = ProviderConfig(
        provider_id="spf_none",
        name="No SPF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_spf()


def test_build_expected_spf_requires_config():
    provider = ProviderConfig(
        provider_id="spf_none",
        name="No SPF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker._build_expected_spf()


def test_spf_no_records_fails():
    provider = ProviderConfig(
        provider_id="spf_missing",
        name="Missing SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["example.test"],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"example.test": ["not-spf"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL


def test_spf_requires_mechanism_base_pass():
    provider = ProviderConfig(
        provider_id="spf_required_mech",
        name="Required Mechanism Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=["a"],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 a -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_accepts_additional_ip4_ip6():
    provider = ProviderConfig(
        provider_id="spf_ip",
        name="IP SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        txt={
            "example.test": [
                "v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 -all",
            ]
        }
    )

    checker = DNSChecker(
        "example.test",
        provider,
        resolver=resolver,
        strict=False,
        additional_spf_ip4=["192.0.2.1"],
        additional_spf_ip6=["2001:db8::1"],
    )
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_required_and_allowed_mechanisms_cover_base():
    provider = ProviderConfig(
        provider_id="spf_required_allowed",
        name="Required/Allowed SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=["a"],
            allowed_mechanisms=["mx"],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 a mx -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_required_mechanism_with_qualifier_passes():
    provider = ProviderConfig(
        provider_id="spf_required_exact",
        name="Required Exact SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=["-ptr"],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 -ptr -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_allowed_mechanism_with_qualifier_passes():
    provider = ProviderConfig(
        provider_id="spf_allowed_exact",
        name="Allowed Exact SPF Provider",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=[],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=["-ptr"],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 -ptr -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS
