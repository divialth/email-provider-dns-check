from provider_check.checker import DNSChecker
from provider_check.provider_config import SRVRecord
from provider_check.status import Status

from tests.checker.srv_support import make_provider_with_srv, make_srv_config
from tests.support import FakeResolver

PRIMARY_REQUIRED = {
    "_sip._tls": [SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")]
}


def test_srv_passes_when_records_match():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status is Status.PASS
    assert result.message == "Required SRV records present"


def test_srv_priority_mismatch_warns_in_non_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(200, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status is Status.WARN
    assert result.message == "SRV priorities or weights differ from expected"
    assert result.details["mismatched"] == {
        "_sip._tls.example.com": [
            {
                "expected": (100, 1, 443, "srv.primary.provider.test."),
                "found": (200, 1, 443, "srv.primary.provider.test."),
            }
        ]
    }


def test_srv_priority_mismatch_pairing_stable():
    provider = make_provider_with_srv(
        make_srv_config(
            required={
                "_sip._tls": [
                    SRVRecord(priority=10, weight=0, port=443, target="srv.primary.provider.test."),
                    SRVRecord(priority=20, weight=0, port=443, target="srv.primary.provider.test."),
                ]
            }
        )
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (40, 1, 443, "srv.primary.provider.test."),
                (30, 2, 443, "srv.primary.provider.test."),
            ],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status is Status.WARN
    assert result.details["mismatched"] == {
        "_sip._tls.example.com": [
            {
                "expected": (10, 0, 443, "srv.primary.provider.test."),
                "found": (30, 2, 443, "srv.primary.provider.test."),
            },
            {
                "expected": (20, 0, 443, "srv.primary.provider.test."),
                "found": (40, 1, 443, "srv.primary.provider.test."),
            },
        ]
    }


def test_srv_priority_mismatch_fails_in_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(200, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.message == "SRV records do not exactly match required configuration"


def test_srv_strict_passes_when_records_match():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.PASS
    assert result.message == "SRV records match required configuration"


def test_srv_missing_records_fail():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(srv={"_sip._tls.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.message == "Missing required SRV records"
    assert result.details["missing"] == {
        "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]
    }


def test_srv_missing_records_fail_in_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(srv={"_sip._tls.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.message == "SRV records do not exactly match required configuration"
    assert result.details["missing"] == {
        "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]
    }


def test_srv_mismatch_and_extra_warn_in_non_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (200, 1, 443, "srv.primary.provider.test."),
                (50, 5, 5061, "srv.extra.provider.test."),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status is Status.WARN
    assert result.message == "SRV priorities or weights differ from expected"
    assert result.details["extra"] == {
        "_sip._tls.example.com": [(50, 5, 5061, "srv.extra.provider.test.")]
    }


def test_srv_extra_records_warn_in_non_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (100, 1, 443, "srv.primary.provider.test."),
                (100, 1, 5061, "srv.extra.provider.test."),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status is Status.WARN
    assert result.message == "Additional SRV records present; required records found"
    assert result.details["extra"] == {
        "_sip._tls.example.com": [(100, 1, 5061, "srv.extra.provider.test.")]
    }


def test_srv_extra_records_fail_in_strict():
    provider = make_provider_with_srv(make_srv_config(required=PRIMARY_REQUIRED))
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (100, 1, 443, "srv.primary.provider.test."),
                (100, 1, 5061, "srv.extra.provider.test."),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.message == "SRV records do not exactly match required configuration"
