from provider_check.checker import DNSChecker

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
