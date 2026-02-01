import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import ProviderConfig, SRVConfig, SRVRecord

from tests.support import FakeResolver


def _build_provider(records):
    return ProviderConfig(
        provider_id="srv_provider",
        name="SRV Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        srv=SRVConfig(records=records),
        txt=None,
        dmarc=None,
    )


def test_srv_passes_when_records_match():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="sipdir.online.lync.com.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [(100, 1, 443, "sipdir.online.lync.com.")],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status == "PASS"


def test_srv_missing_records_fail():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="sipdir.online.lync.com.")
            ]
        }
    )
    resolver = FakeResolver(srv={"_sip._tls.example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_srv()

    assert result.status == "FAIL"
    assert "_sip._tls.example.com" in result.details["missing"]


def test_srv_extra_records_warn_in_non_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="sipdir.online.lync.com.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (100, 1, 443, "sipdir.online.lync.com."),
                (100, 1, 5061, "sipfed.online.lync.com."),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_srv()

    assert result.status == "WARN"
    assert "_sip._tls.example.com" in result.details["extra"]


def test_srv_extra_records_fail_in_strict():
    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="sipdir.online.lync.com.")
            ]
        }
    )
    resolver = FakeResolver(
        srv={
            "_sip._tls.example.com": [
                (100, 1, 443, "sipdir.online.lync.com."),
                (100, 1, 5061, "sipfed.online.lync.com."),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_srv()

    assert result.status == "FAIL"


def test_srv_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_srv(self, name: str):
            raise DnsLookupError("SRV", name, RuntimeError("timeout"))

    provider = _build_provider(
        {
            "_sip._tls": [
                SRVRecord(priority=100, weight=1, port=443, target="sipdir.online.lync.com.")
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_srv()

    assert result.status == "UNKNOWN"


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
