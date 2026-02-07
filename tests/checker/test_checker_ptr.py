import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import PTRConfig, ProviderConfig
from provider_check.status import Status

from tests.support import FakeResolver


def _build_provider(records, optional=None) -> ProviderConfig:
    config = PTRConfig(required=records, optional=optional or {})
    return ProviderConfig(
        provider_id="ptr_provider",
        name="PTR Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        ptr=config,
        txt=None,
        dmarc=None,
    )


def test_ptr_records_pass_when_present():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["Mail.Example.Test"]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_ptr()

    assert result.status is Status.PASS


def test_ptr_records_pass_when_reverse_name_has_no_trailing_dot():
    provider = _build_provider({"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_ptr()

    assert result.status is Status.PASS


def test_ptr_records_missing_fail():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_ptr()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {"10.2.0.192.in-addr.arpa": ["mail.example.test."]}


def test_ptr_records_extra_warn_in_non_strict():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(
        ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test.", "mx.example.test."]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=False)

    result = checker.check_ptr()

    assert result.status is Status.WARN
    assert result.details["extra"] == {"10.2.0.192.in-addr.arpa": ["mx.example.test."]}


def test_ptr_records_extra_fail_in_strict():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(
        ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test.", "mx.example.test."]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_ptr()

    assert result.status is Status.FAIL
    assert result.message == "PTR records do not exactly match required configuration"


def test_ptr_records_strict_pass():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=resolver, strict=True)

    result = checker.check_ptr()

    assert result.status is Status.PASS


def test_ptr_records_strict_missing_fail():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver(), strict=True)

    result = checker.check_ptr()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {"10.2.0.192.in-addr.arpa": ["mail.example.test."]}


def test_ptr_optional_missing_warns():
    provider = _build_provider({}, optional={"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_ptr_optional()

    assert result.status is Status.WARN
    assert result.optional is True
    assert result.details["missing"] == {"10.2.0.192.in-addr.arpa": ["mail.example.test."]}


def test_ptr_optional_present_passes():
    provider = _build_provider({}, optional={"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_ptr_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_ptr_optional_extra_fails():
    provider = _build_provider({}, optional={"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(
        ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test.", "mx.example.test."]}
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_ptr_optional()

    assert result.status is Status.FAIL
    assert result.optional is True
    assert result.details["extra"] == {"10.2.0.192.in-addr.arpa": ["mx.example.test."]}


def test_ptr_optional_no_records_passes():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]}, optional={})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = checker.check_ptr_optional()

    assert result.status is Status.PASS
    assert result.optional is True


def test_ptr_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_ptr(self, name: str):
            raise DnsLookupError("PTR", name, RuntimeError("timeout"))

    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_ptr()

    assert result.status is Status.UNKNOWN


def test_ptr_optional_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_ptr(self, name: str):
            raise DnsLookupError("PTR", name, RuntimeError("timeout"))

    provider = _build_provider({}, optional={"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_ptr_optional()

    assert result.status is Status.UNKNOWN
    assert result.optional is True


def test_ptr_requires_config():
    provider = ProviderConfig(
        provider_id="no_ptr",
        name="No PTR Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        ptr=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="PTR configuration not available for provider"):
        checker.check_ptr()


def test_ptr_optional_requires_config():
    provider = ProviderConfig(
        provider_id="no_ptr",
        name="No PTR Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        ptr=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="PTR configuration not available for provider"):
        checker.check_ptr_optional()


def test_run_checks_includes_ptr():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "PTR" and not result.optional for result in results)


def test_run_checks_includes_optional_ptr():
    provider = _build_provider({}, optional={"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    resolver = FakeResolver(ptr={"10.2.0.192.in-addr.arpa": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "PTR" and result.optional for result in results)


def test_normalize_ptr_name_replaces_domain_placeholder():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    assert checker._normalize_ptr_name("{domain}") == "example.com"


def test_normalize_ptr_name_falls_back_for_non_reverse_labels():
    provider = _build_provider({"10.2.0.192.in-addr.arpa.": ["mail.example.test."]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    assert checker._normalize_ptr_name("ptr-label") == "ptr-label.example.com"
