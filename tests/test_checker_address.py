import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import AddressConfig, ProviderConfig
from provider_check.status import Status

from tests.support import FakeResolver


def _build_provider(record_type: str, records, optional=None) -> ProviderConfig:
    config = AddressConfig(required=records, optional=optional or {})
    data = {
        "provider_id": f"{record_type.lower()}_provider",
        "name": f"{record_type} Provider",
        "version": "1",
        "mx": None,
        "spf": None,
        "dkim": None,
        "txt": None,
        "dmarc": None,
        "a": None,
        "aaaa": None,
    }
    if record_type == "A":
        data["a"] = config
    else:
        data["aaaa"] = config
    return ProviderConfig(**data)


def _resolver_kwargs(record_type: str, mapping):
    if record_type == "A":
        return {"a": mapping}
    return {"aaaa": mapping}


def _address_value(record_type: str) -> str:
    if record_type == "A":
        return "192.0.2.1"
    return "2001:db8::1"


@pytest.mark.parametrize(
    "record_type,addresses",
    [("A", ["192.0.2.1", "192.0.2.2"]), ("AAAA", ["2001:db8::1"])],
)
def test_address_records_pass_when_present(record_type, addresses):
    provider = _build_provider(record_type, {"@": addresses})
    domain = "example.com"
    resolver = FakeResolver(**_resolver_kwargs(record_type, {domain: addresses}))
    checker = DNSChecker(domain, provider, resolver=resolver)

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.PASS


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_records_missing_fail(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {"example.com": [_address_value(record_type)]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_records_extra_warn_in_non_strict(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type), "192.0.2.2"]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.WARN
    assert result.details["extra"] == {"example.com": ["192.0.2.2"]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_records_extra_fail_in_strict(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type), "192.0.2.2"]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver, strict=True)

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.FAIL
    assert result.details["extra"] == {"example.com": ["192.0.2.2"]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_records_strict_pass(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type)]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver, strict=True)

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.PASS


def test_address_records_canonicalize_ipv6():
    provider = _build_provider("AAAA", {"@": ["2001:db8:0:0:0:0:0:1"]})
    resolver = FakeResolver(aaaa={"example.com": ["2001:db8::1"]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_aaaa()

    assert result.status is Status.PASS


def test_address_records_fallback_normalization_for_invalid_values():
    provider = _build_provider("A", {"@": ["NOT-AN-IP"]})
    resolver = FakeResolver(a={"example.com": ["not-an-ip"]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    result = checker.check_a()

    assert result.status is Status.PASS


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_records_strict_missing_fails(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver(), strict=True)

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.FAIL
    assert result.details["missing"] == {"example.com": [_address_value(record_type)]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_missing_warns(record_type):
    provider = _build_provider(record_type, {}, optional={"@": [_address_value(record_type)]})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = getattr(checker, f"check_{record_type.lower()}_optional")()

    assert result.status is Status.WARN
    assert result.optional is True
    assert result.details["missing"] == {"example.com": [_address_value(record_type)]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_no_records_passes(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]}, optional={})
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    result = getattr(checker, f"check_{record_type.lower()}_optional")()

    assert result.status is Status.PASS
    assert result.optional is True


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_present_passes(record_type):
    provider = _build_provider(record_type, {}, optional={"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type)]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver)

    result = getattr(checker, f"check_{record_type.lower()}_optional")()

    assert result.status is Status.PASS
    assert result.optional is True


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_extra_fails(record_type):
    provider = _build_provider(record_type, {}, optional={"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type), "192.0.2.2"]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver)

    result = getattr(checker, f"check_{record_type.lower()}_optional")()

    assert result.status is Status.FAIL
    assert result.optional is True
    assert result.details["extra"] == {"example.com": ["192.0.2.2"]}


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_lookup_error_returns_unknown(record_type):
    class FailingResolver(FakeResolver):
        def get_a(self, name: str):
            raise DnsLookupError("A", name, RuntimeError("timeout"))

        def get_aaaa(self, name: str):
            raise DnsLookupError("AAAA", name, RuntimeError("timeout"))

    provider = _build_provider(record_type, {}, optional={"@": [_address_value(record_type)]})
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = getattr(checker, f"check_{record_type.lower()}_optional")()

    assert result.status is Status.UNKNOWN
    assert result.optional is True


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_lookup_error_returns_unknown(record_type):
    class FailingResolver(FakeResolver):
        def get_a(self, name: str):
            raise DnsLookupError("A", name, RuntimeError("timeout"))

        def get_aaaa(self, name: str):
            raise DnsLookupError("AAAA", name, RuntimeError("timeout"))

    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = getattr(checker, f"check_{record_type.lower()}")()

    assert result.status is Status.UNKNOWN


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_requires_config(record_type):
    if record_type == "A":
        provider = ProviderConfig(
            provider_id="no_a",
            name="No A Provider",
            version="1",
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
            a=None,
        )
    else:
        provider = ProviderConfig(
            provider_id="no_aaaa",
            name="No AAAA Provider",
            version="1",
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
            aaaa=None,
        )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        getattr(checker, f"check_{record_type.lower()}")()


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_address_optional_requires_config(record_type):
    if record_type == "A":
        provider = ProviderConfig(
            provider_id="no_a",
            name="No A Provider",
            version="1",
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
            a=None,
        )
    else:
        provider = ProviderConfig(
            provider_id="no_aaaa",
            name="No AAAA Provider",
            version="1",
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
            aaaa=None,
        )
    checker = DNSChecker("example.com", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        getattr(checker, f"check_{record_type.lower()}_optional")()


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_run_checks_includes_address(record_type):
    provider = _build_provider(record_type, {"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type)]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == record_type for result in results)


@pytest.mark.parametrize("record_type", ["A", "AAAA"])
def test_run_checks_includes_optional_address(record_type):
    provider = _build_provider(record_type, {}, optional={"@": [_address_value(record_type)]})
    domain = "example.com"
    resolver = FakeResolver(
        **_resolver_kwargs(record_type, {domain: [_address_value(record_type)]})
    )
    checker = DNSChecker(domain, provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == record_type and result.optional for result in results)
