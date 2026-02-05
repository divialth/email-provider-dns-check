import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import CAAConfig, CAARecord, ProviderConfig
from provider_check.status import Status

from tests.support import FakeResolver


def _build_provider(records, records_optional=None):
    return ProviderConfig(
        provider_id="caa_provider",
        name="CAA Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=None,
        caa=CAAConfig(records=records, records_optional=records_optional or {}),
        srv=None,
        txt=None,
        dmarc=None,
    )


def test_caa_passes_when_required_records_present():
    provider = _build_provider({"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]})
    resolver = FakeResolver(
        caa={"example.com": [(0, "issue", "ca.example.test")]},
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_caa()

    assert result.status is Status.PASS


def test_caa_fails_when_required_records_missing():
    provider = _build_provider({"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]})
    resolver = FakeResolver(caa={"example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_caa()

    assert result.status is Status.FAIL
    assert "missing" in result.details


def test_caa_iodef_value_is_case_sensitive():
    provider = _build_provider(
        {"@": [CAARecord(flags=0, tag="iodef", value="https://example.test/Case")]}
    )
    resolver = FakeResolver(caa={"example.com": [(0, "iodef", "https://example.test/case")]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_caa()

    assert result.status is Status.FAIL
    assert "missing" in result.details


def test_caa_strict_fails_with_extra_records():
    provider = _build_provider({"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]})
    resolver = FakeResolver(
        caa={
            "example.com": [
                (0, "issue", "ca.example.test"),
                (0, "issuewild", "ca.example.test"),
            ]
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_caa()

    assert result.status is Status.FAIL
    assert "extra" in result.details


def test_caa_strict_missing_records_reports_missing_details():
    provider = _build_provider({"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]})
    resolver = FakeResolver(caa={"example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_caa()

    assert result.status is Status.FAIL
    assert "missing" in result.details


def test_caa_optional_warns_when_missing():
    provider = _build_provider(
        {},
        records_optional={"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]},
    )
    resolver = FakeResolver(caa={"example.com": []})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_caa_optional()

    assert result.status is Status.WARN
    assert result.optional is True


def test_caa_optional_passes_when_present():
    provider = _build_provider(
        {},
        records_optional={"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]},
    )
    resolver = FakeResolver(caa={"example.com": [(0, "issue", "ca.example.test")]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_caa_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_caa_optional_returns_pass_when_no_optional_required():
    provider = _build_provider({})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_caa_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_caa_requires_config():
    provider = ProviderConfig(
        provider_id="no_caa",
        name="No CAA Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=None,
        srv=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="CAA configuration not available"):
        checker.check_caa()


def test_caa_optional_requires_config():
    provider = ProviderConfig(
        provider_id="no_caa",
        name="No CAA Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=None,
        srv=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="CAA configuration not available"):
        checker.check_caa_optional()


def test_caa_dns_lookup_error_returns_unknown():
    provider = _build_provider({"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]})

    class ErrorResolver:
        def get_caa(self, name: str):
            raise DnsLookupError("CAA", name, RuntimeError("boom"))

    checker = DNSChecker("example.com", provider, resolver=ErrorResolver())

    result = checker.check_caa()

    assert result.status is Status.UNKNOWN


def test_caa_optional_dns_lookup_error_returns_unknown():
    provider = _build_provider(
        {},
        records_optional={"@": [CAARecord(flags=0, tag="issue", value="ca.example.test")]},
    )

    class ErrorResolver:
        def get_caa(self, name: str):
            raise DnsLookupError("CAA", name, RuntimeError("boom"))

    checker = DNSChecker("example.com", provider, resolver=ErrorResolver())

    result = checker.check_caa_optional()

    assert result.status is Status.UNKNOWN
