from provider_check.checker import DNSChecker
from provider_check.provider_config import CNAMEConfig, ProviderConfig, SRVConfig, SRVRecord

from tests.support import BASE_PROVIDER, FakeResolver


def test_strict_success():
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

    assert all(r.status == "PASS" for r in results)


def test_run_checks_includes_cname_and_srv():
    provider = ProviderConfig(
        provider_id="check_types",
        name="Check Types Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=CNAMEConfig(records={"sip": "sip.provider.test."}),
        srv=SRVConfig(
            records={
                "_sip._tls": [
                    SRVRecord(
                        priority=100,
                        weight=1,
                        port=443,
                        target="sip.provider.test.",
                    )
                ]
            }
        ),
        txt=None,
        dmarc=None,
    )
    domain = "example.com"
    resolver = FakeResolver(
        cname={"sip.example.com": "sip.provider.test."},
        srv={"_sip._tls.example.com": [(100, 1, 443, "sip.provider.test.")]},
    )

    checker = DNSChecker(domain, provider, resolver=resolver)

    results = checker.run_checks()
    record_types = {result.record_type for result in results}

    assert {"CNAME", "SRV"} <= record_types


def test_normalize_record_name_variants():
    provider = ProviderConfig(
        provider_id="normalize",
        name="Normalize Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider)

    assert checker._normalize_record_name("@") == "example.com"
    assert checker._normalize_record_name("{domain}") == "example.com"
    assert checker._normalize_record_name("service.example.com.") == "service.example.com"
    assert checker._normalize_record_name("service.example.com") == "service.example.com"
