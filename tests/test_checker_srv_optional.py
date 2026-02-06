import pytest

from provider_check.checker import DNSChecker
from provider_check.provider_config import SRVRecord
from provider_check.status import Status

from tests.checker_srv_support import make_provider_with_srv, make_srv_config
from tests.support import FakeResolver

OPTIONAL_AUTODISCOVER = {
    "_autodiscover._tcp": [
        SRVRecord(priority=0, weight=0, port=443, target="autodiscover.provider.test.")
    ]
}


def test_srv_optional_missing_warns():
    provider = make_provider_with_srv(
        make_srv_config(
            required={
                "_sip._tls": [
                    SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
                ]
            },
            optional=OPTIONAL_AUTODISCOVER,
        )
    )
    resolver = FakeResolver(
        srv={"_sip._tls.example.com": [(100, 1, 443, "srv.primary.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.WARN
    assert result.message == "SRV optional records missing"
    assert result.optional is True
    assert result.details["missing"] == {
        "_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]
    }


def test_srv_optional_present_passes():
    provider = make_provider_with_srv(make_srv_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.PASS
    assert result.message == "SRV optional records present"
    assert result.optional is True


def test_srv_optional_mismatch_fails():
    provider = make_provider_with_srv(make_srv_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "wrong.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv_optional()

    assert result.status is Status.FAIL
    assert result.message == "SRV optional records mismatched"
    assert result.optional is True
    assert result.details["extra"] == {
        "_autodiscover._tcp.example.com": [(0, 0, 443, "wrong.provider.test.")]
    }


def test_srv_optional_no_records_passes():
    provider = make_provider_with_srv(
        make_srv_config(
            required={
                "_sip._tls": [
                    SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
                ]
            }
        )
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_srv_optional()

    assert result.status is Status.PASS
    assert result.message == "No optional SRV records required"
    assert result.optional is True


def test_srv_requires_config():
    provider = make_provider_with_srv(
        None,
        provider_id="no_srv",
        name="No SRV Provider",
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="SRV configuration not available for provider"):
        checker.check_srv()


def test_srv_optional_requires_config():
    provider = make_provider_with_srv(
        None,
        provider_id="no_srv",
        name="No SRV Provider",
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="SRV configuration not available for provider"):
        checker.check_srv_optional()


def test_run_checks_includes_optional_srv():
    provider = make_provider_with_srv(make_srv_config(optional=OPTIONAL_AUTODISCOVER))
    resolver = FakeResolver(
        srv={"_autodiscover._tcp.example.com": [(0, 0, 443, "autodiscover.provider.test.")]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "SRV" and result.optional for result in results)
