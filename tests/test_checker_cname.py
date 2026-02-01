import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import CNAMEConfig, ProviderConfig

from tests.support import FakeResolver


def _build_provider(records):
    return ProviderConfig(
        provider_id="cname_provider",
        name="CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=CNAMEConfig(records=records),
        txt=None,
        dmarc=None,
    )


def test_cname_passes_when_records_match():
    provider = _build_provider(
        {
            "sip": "sipdir.online.lync.com.",
            "lyncdiscover": "webdir.online.lync.com.",
        }
    )
    domain = "example.com"
    resolver = FakeResolver(
        cname={
            "sip.example.com": "sipdir.online.lync.com.",
            "lyncdiscover.example.com": "webdir.online.lync.com.",
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver)

    result = checker.check_cname()

    assert result.status == "PASS"


def test_cname_missing_records_fail():
    provider = _build_provider({"sip": "sipdir.online.lync.com."})
    resolver = FakeResolver(cname={})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_cname()

    assert result.status == "FAIL"
    assert "sip.example.com" in result.details["missing"]


def test_cname_mismatch_records_fail():
    provider = _build_provider({"sip": "sipdir.online.lync.com."})
    resolver = FakeResolver(cname={"sip.example.com": "wrong.example."})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_cname()

    assert result.status == "FAIL"
    assert "sip.example.com" in result.details["mismatched"]


def test_cname_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_cname(self, name: str):
            raise DnsLookupError("CNAME", name, RuntimeError("timeout"))

    provider = _build_provider({"sip": "sipdir.online.lync.com."})
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_cname()

    assert result.status == "UNKNOWN"


def test_cname_requires_config():
    provider = ProviderConfig(
        provider_id="no_cname",
        name="No CNAME Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_cname()
