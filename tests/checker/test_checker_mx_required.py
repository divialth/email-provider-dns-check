from provider_check.checker import DNSChecker
from provider_check.provider_config import MXRecord
from provider_check.status import Status

from tests.checker.mx_support import make_mx_config, make_provider_with_mx
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
    assert mx_result.message == "No MX records found"


def test_mx_priorities_match_pass():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ]
        ),
        provider_id="mx_priorities",
        name="MX Priority Provider",
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
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ]
        ),
        provider_id="mx_priorities",
        name="MX Priority Provider",
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
    assert mx_result.message == "MX priorities differ from expected"
    assert "mismatched" in mx_result.details


def test_mx_strict_extra_hosts_fail():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test."),
                MXRecord(host="mx2.example.test."),
            ]
        ),
        provider_id="mx_strict",
        name="Strict MX Provider",
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
    assert result.message == "MX records do not exactly match required configuration"
    assert "extra" in result.details


def test_mx_missing_required_non_strict_fails():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test."),
                MXRecord(host="mx2.example.test."),
            ]
        ),
        provider_id="mx_missing",
        name="Missing MX Provider",
    )
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_mx()

    assert result.status is Status.FAIL
    assert result.message == "Missing required MX host(s)"
    assert "missing" in result.details


def test_mx_required_empty_passes():
    provider = make_provider_with_mx(
        make_mx_config(),
        provider_id="mx_empty",
        name="Empty MX Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    result = checker.check_mx()

    assert result.status is Status.PASS
    assert result.message == "No MX records required"


def test_mx_extra_hosts_warns():
    provider = make_provider_with_mx(
        make_mx_config(required=[MXRecord(host="mx1.example.test.")]),
        provider_id="mx_extra",
        name="Extra MX Provider",
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)

    result = checker.check_mx()

    assert result.status is Status.WARN
    assert result.message == "Additional MX hosts present; required hosts found"
    assert "extra" in result.details


def test_mx_priority_mismatch_with_extra_warns():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ]
        ),
        provider_id="mx_mismatch",
        name="MX Mismatch Provider",
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
    assert result.message == "MX priorities differ from expected"
    assert "mismatched" in result.details
    assert "extra" in result.details


def test_mx_strict_mismatch_includes_details():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[
                MXRecord(host="mx1.example.test.", priority=10),
                MXRecord(host="mx2.example.test.", priority=20),
            ]
        ),
        provider_id="mx_strict_mismatch",
        name="Strict MX Mismatch Provider",
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 5), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)

    result = checker.check_mx()

    assert result.status is Status.FAIL
    assert result.message == "MX records do not exactly match required configuration"
    assert "mismatched" in result.details
