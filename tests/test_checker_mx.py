import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import MXConfig, MXRecord, ProviderConfig
from provider_check.status import Status

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

    assert mx_result.status is Status.FAIL


def test_mx_priorities_match_pass():
    provider = ProviderConfig(
        provider_id="mx_priorities",
        name="MX Priority Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ],
            optional=[],
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

    assert mx_result.status is Status.PASS


def test_mx_priority_mismatch_warns():
    provider = ProviderConfig(
        provider_id="mx_priorities",
        name="MX Priority Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ],
            optional=[],
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

    assert mx_result.status is Status.WARN
    assert "mismatched" in mx_result.details


def test_mx_requires_config():
    provider = ProviderConfig(
        provider_id="no_mx",
        name="No MX Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )

    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_mx()


def test_mx_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_mx(self, domain: str):
            raise DnsLookupError("MX", domain, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="mx_provider",
        name="MX Provider",
        version="1",
        mx=MXConfig(required=[MXRecord(host="mx1.example.test.")], optional=[]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_mx()

    assert result.status is Status.UNKNOWN


def test_mx_strict_extra_hosts_fail():
    provider = ProviderConfig(
        provider_id="mx_strict",
        name="Strict MX Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test."),
                MXRecord(host="mx2.example.test."),
            ],
            optional=[],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={
            "example.test": [
                ("mx1.example.test.", 10),
                ("mx2.example.test.", 20),
                ("mx3.example.test.", 30),
            ]
        }
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)

    result = checker.check_mx()

    assert result.status is Status.FAIL
    assert "extra" in result.details


def test_mx_missing_required_non_strict_fails():
    provider = ProviderConfig(
        provider_id="mx_missing",
        name="Missing MX Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test."),
                MXRecord(host="mx2.example.test."),
            ],
            optional=[],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_mx()

    assert result.status is Status.FAIL
    assert "missing" in result.details


def test_mx_required_empty_passes():
    provider = ProviderConfig(
        provider_id="mx_empty",
        name="Empty MX Provider",
        version="1",
        mx=MXConfig(required=[], optional=[]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    result = checker.check_mx()

    assert result.status is Status.PASS


def test_mx_extra_hosts_warns():
    provider = ProviderConfig(
        provider_id="mx_extra",
        name="Extra MX Provider",
        version="1",
        mx=MXConfig(required=[MXRecord(host="mx1.example.test.")], optional=[]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_mx()

    assert result.status is Status.WARN
    assert "extra" in result.details


def test_mx_optional_priority_mismatch_warns_with_string_records():
    provider = ProviderConfig(
        provider_id="mx_optional_mismatch",
        name="MX Optional Mismatch Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=10)],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(mx={"example.test": ["mx2.example.test."]})
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.WARN
    assert "mismatched" in result.details


def test_mx_priority_mismatch_with_extra_warns():
    provider = ProviderConfig(
        provider_id="mx_mismatch",
        name="MX Mismatch Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ],
            optional=[],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={
            "example.test": [
                ("mx1.example.test.", 5),
                ("mx2.example.test.", 20),
                ("mx3.example.test.", 30),
            ]
        }
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_mx()

    assert result.status is Status.WARN
    assert "mismatched" in result.details
    assert "extra" in result.details


def test_mx_strict_mismatch_includes_details():
    provider = ProviderConfig(
        provider_id="mx_strict_mismatch",
        name="Strict MX Mismatch Provider",
        version="1",
        mx=MXConfig(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ],
            optional=[],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 5), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)

    result = checker.check_mx()

    assert result.status is Status.FAIL
    assert "mismatched" in result.details


def test_mx_optional_missing_warns():
    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=20)],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.WARN
    assert result.optional is True


def test_mx_optional_present_passes():
    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=20)],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_mx_optional_no_records_passes():
    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=MXConfig(required=[MXRecord(host="mx1.example.test.")], optional=[]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    result = checker.check_mx_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_mx_optional_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_mx(self, domain: str):
            raise DnsLookupError("MX", domain, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.")],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_mx_optional()

    assert result.status is Status.UNKNOWN
    assert result.optional is True


def test_mx_optional_requires_config():
    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_mx_optional()


def test_run_checks_includes_optional_mx():
    provider = ProviderConfig(
        provider_id="mx_optional",
        name="MX Optional Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.")],
        ),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "MX" and result.optional for result in results)
