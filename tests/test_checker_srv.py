import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import ProviderConfig, SRVConfig, SRVRecord
from provider_check.status import Status

from tests.support import FakeResolver


def _build_provider(records, optional=None):
    return ProviderConfig(
        provider_id="srv_provider",
        name="SRV Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        srv=SRVConfig(required=records, optional=optional or {}),
        txt=None,
        dmarc=None,
    )


def test_srv_passes_when_records_match():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status is Status.PASS


def test_srv_priority_mismatch_warns_in_non_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(200, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status is Status.WARN
    assert result.details["mismatched"] == {
        "_sip._tls.example.com": [
            {
                "expected": (100, 1, 443, "srv.primary.provider.test."),
                "found": (200, 1, 443, "srv.primary.provider.test."),
            }
        ]
    }


def test_srv_priority_mismatch_pairing_stable():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=10, weight=0, port=443, target="srv.primary.provider.test."),
                SRVRecord(priority=20, weight=0, port=443, target="srv.primary.provider.test."),
            ]
        }
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
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(200, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.FAIL


def test_srv_strict_passes_when_records_match():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.PASS


def test_srv_missing_records_fail():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(srv={"_sip._tls.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {
        "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]
    }


def test_srv_missing_records_fail_in_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    resolver = FakeResolver(srv={"_sip._tls.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {
        "_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]
    }


def test_srv_mismatch_and_extra_warn_in_non_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
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
    assert result.details["extra"] == {
        "_sip._tls.example.com": [(50, 5, 5061, "srv.extra.provider.test.")]
    }


def test_srv_extra_records_warn_in_non_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
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
    assert result.details["extra"] == {
        "_sip._tls.example.com": [(100, 1, 5061, "srv.extra.provider.test.")]
    }


def test_srv_extra_records_fail_in_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
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


def test_srv_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_srv(self, name: str):
            raise DnsLookupError("SRV", name, RuntimeError("timeout"))

    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_srv()

    assert result.status is Status.UNKNOWN


def test_srv_optional_missing_warns():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        },
        optional={
            "_autodiscover._tcp": [
                SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
            ]
        },
    )
    resolver = FakeResolver(
        srv={"_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.WARN
    assert result.optional is True
    assert result.details["missing"] == {
        "_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]
    }


def test_srv_optional_present_passes():
    provider = _build_provider(
        {},
        optional={
            "_autodiscover._tcp": [
                SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
            ]
        },
    )
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_srv_optional_mismatch_fails():
    provider = _build_provider(
        {},
        optional={
            "_autodiscover._tcp": [
                SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
            ]
        },
    )
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "wrong.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.FAIL
    assert result.optional is True
    assert result.details["extra"] == {
        "_autodiscover._tcp.example.com": [(0, 0, 443, "wrong.provider.test.")]
    }


def test_srv_optional_no_records_passes():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
            ]
        },
        optional={},
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_srv_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_srv_optional_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_srv(self, name: str):
            raise DnsLookupError("SRV", name, RuntimeError("timeout"))

    provider = _build_provider(
        {},
        optional={
            "_autodiscover._tcp": [
                SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
            ]
        },
    )
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_srv_optional()

    assert result.status is Status.UNKNOWN
    assert result.optional is True


def test_srv_optional_requires_config():
    provider = ProviderConfig(
        provider_id="no_srv",
        name="No SRV Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        srv=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_srv_optional()


def test_run_checks_includes_optional_srv():
    provider = _build_provider(
        {},
        optional={
            "_autodiscover._tcp": [
                SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
            ]
        },
    )
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "SRV" and result.optional for result in results)


def test_srv_requires_config():
    provider = ProviderConfig(
        provider_id="no_srv",
        name="No SRV Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        srv=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_srv()
