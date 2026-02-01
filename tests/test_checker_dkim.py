from provider_check.checker import DNSChecker
from provider_check.provider_config import DKIMConfig, ProviderConfig

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

    assert dkim.status == "PASS"
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
            selectors=["s1"],
            record_type="txt",
            target_template=None,
            txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
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
    assert dkim_result.status == "PASS"


def test_dkim_txt_values_mismatch_warns():
    provider = ProviderConfig(
        provider_id="dkim_txt",
        name="DKIM TXT Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            selectors=["s1"],
            record_type="txt",
            target_template=None,
            txt_values={"s1": "v=DKIM1; k=rsa; p=ABC123"},
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
    assert dkim_result.status == "WARN"
    assert "mismatched" in dkim_result.details
