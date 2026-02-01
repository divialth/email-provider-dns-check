from provider_check.checker import DNSChecker
from provider_check.provider_config import MXConfig, ProviderConfig

from tests.support import BASE_PROVIDER, FakeResolver


def test_missing_mx_fails():
    domain = "broken.example"
    resolver = FakeResolver(
        mx={domain: []},
        txt={
            domain: ["v=spf1 include:dummy.test -all"],
            f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:postmaster@broken.example"],
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
    mx_result = next(r for r in results if r.record_type == "MX")

    assert mx_result.status == "FAIL"


def test_mx_priorities_match_pass():
    provider = ProviderConfig(
        provider_id="mx_priorities",
        name="MX Priority Provider",
        version="1",
        mx=MXConfig(
            hosts=["mx1.example.test.", "mx2.example.test."],
            priorities={"mx1.example.test.": 10, "mx2.example.test.": 20},
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        mx={
            domain: [
                ("mx1.example.test.", 10),
                ("mx2.example.test.", 20),
            ]
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()
    mx_result = next(r for r in results if r.record_type == "MX")

    assert mx_result.status == "PASS"


def test_mx_priority_mismatch_warns():
    provider = ProviderConfig(
        provider_id="mx_priorities",
        name="MX Priority Provider",
        version="1",
        mx=MXConfig(
            hosts=["mx1.example.test.", "mx2.example.test."],
            priorities={"mx1.example.test.": 10, "mx2.example.test.": 20},
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        mx={
            domain: [
                ("mx1.example.test.", 5),
                ("mx2.example.test.", 20),
            ]
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()
    mx_result = next(r for r in results if r.record_type == "MX")

    assert mx_result.status == "WARN"
    assert "mismatched" in mx_result.details
