import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import DKIMConfig, DKIMRequired, ProviderConfig
from provider_check.status import Status

from tests.support import BASE_PROVIDER, FakeResolver


def test_dkim_pass_includes_selector_details():
    domain = "example.com"
    resolver = FakeResolver(
        mx={domain: ["mx1.dummy.test.", "mx2.dummy.test."]},
        txt={
            domain: ["v=spf1 include:dummy.test -all"],
            f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:postmaster@example.com"],
        },
        cname={
            f"DUMMY1._domainkey.{domain}": "DUMMY1._domainkey.dummy.test.",
            f"DUMMY2._domainkey.{domain}": "DUMMY2._domainkey.dummy.test.",
            f"DUMMY3._domainkey.{domain}": "DUMMY3._domainkey.dummy.test.",
            f"DUMMY4._domainkey.{domain}": "DUMMY4._domainkey.dummy.test.",
        },
    )

    checker = DNSChecker(domain, BASE_PROVIDER, resolver=resolver, strict=True)
    results = checker.run_checks()
    dkim = next(r for r in results if r.record_type == "DKIM")

    assert dkim.status is Status.PASS
    assert "selectors" in dkim.details
    assert len(dkim.details["selectors"]) == 4


def test_dkim_txt_values_pass():
    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="txt",
                target_template=None,
                txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
            )
        ),
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"s1._domainkey.{domain}": ["v=DKIM1; k=rsa; p=ABC123"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dkim_result = next(r for r in results if r.record_type == "DKIM")
    assert dkim_result.status is Status.PASS


def test_dkim_txt_values_mismatch_warns():
    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="txt",
                target_template=None,
                txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
            )
        ),
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"s1._domainkey.{domain}": ["v=DKIM1; k=rsa; p=DIFFERENT"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dkim_result = next(r for r in results if r.record_type == "DKIM")
    assert dkim_result.status is Status.WARN
    assert "mismatched" in dkim_result.details


def test_dkim_requires_config():
    provider = ProviderConfig(
        provider_id="dkim_none",
        name="No DKIM Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_dkim()


def test_dkim_cname_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_cname(self, name: str):
            raise DnsLookupError("CNAME", name, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="dkim_cname",
        name="DKIM CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="cname",
                target_template="{selector}._domainkey.example.test.",
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_dkim()

    assert result.status is Status.UNKNOWN


def test_dkim_cname_mismatch_warns():
    provider = ProviderConfig(
        provider_id="dkim_cname",
        name="DKIM CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="cname",
                target_template="{selector}._domainkey.example.test.",
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(cname={"s1._domainkey.example.test": "wrong.target.example.test."})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_dkim()

    assert result.status is Status.WARN
    assert "mismatched" in result.details


def test_dkim_cname_invalid_template_returns_unknown():
    provider = ProviderConfig(
        provider_id="dkim_cname",
        name="DKIM CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="cname",
                target_template="{selector}.{unknown}.example.test.",
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver(), strict=False)

    result = checker.check_dkim()

    assert result.status is Status.UNKNOWN
    assert result.message == "Invalid DKIM target template"
    assert "template" in result.details


def test_dkim_cname_missing_template_returns_unknown():
    provider = ProviderConfig(
        provider_id="dkim_cname",
        name="DKIM CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="cname",
                target_template=None,
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver(), strict=False)

    result = checker.check_dkim()

    assert result.status is Status.UNKNOWN
    assert result.message == "Invalid DKIM target template"
    assert result.details["error"] == "missing target_template"


def test_dkim_txt_missing_selector_fails():
    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="txt",
                target_template=None,
                txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
            )
        ),
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_dkim()

    assert result.status is Status.FAIL
    assert "missing" in result.details


def test_dkim_txt_without_expected_value_marks_present():
    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="txt",
                target_template=None,
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(txt={"s1._domainkey.example.test": ["v=DKIM1; k=rsa; p=ABC123"]})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_dkim()

    assert result.status is Status.PASS
    assert result.details["selectors"]["s1._domainkey.example.test"] == "present"


def test_dkim_txt_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, name: str):
            raise DnsLookupError("TXT", name, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["s1"],
                record_type="txt",
                target_template=None,
                txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
            )
        ),
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_dkim()

    assert result.status is Status.UNKNOWN
