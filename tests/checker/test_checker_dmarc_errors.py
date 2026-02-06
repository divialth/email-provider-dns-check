import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.status import Status

from tests.checker.dmarc_support import make_dmarc_config, make_provider_with_dmarc
from tests.support import FakeResolver


def test_dmarc_requires_config():
    provider = make_provider_with_dmarc(
        None,
        provider_id="dmarc_none",
        name="No DMARC Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_dmarc()


def test_dmarc_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, domain: str):
            raise DnsLookupError("TXT", domain, RuntimeError("timeout"))

    provider = make_provider_with_dmarc(
        make_dmarc_config(),
        provider_id="dmarc_required",
        name="DMARC Required Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_dmarc()

    assert result.status is Status.UNKNOWN


def test_dmarc_rua_mailto_rejects_empty_values():
    provider = make_provider_with_dmarc(
        make_dmarc_config(),
        provider_id="dmarc_rua_invalid",
        name="DMARC Invalid RUA",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        DNSChecker("example.test", provider, dmarc_rua_mailto=[""])

    with pytest.raises(ValueError, match="must include an address"):
        DNSChecker("example.test", provider, dmarc_rua_mailto=["mailto:"])

    with pytest.raises(ValueError, match="must not be empty"):
        DNSChecker("example.test", provider, dmarc_ruf_mailto=[""])

    with pytest.raises(ValueError, match="must include an address"):
        DNSChecker("example.test", provider, dmarc_ruf_mailto=["mailto:"])


def test_dmarc_helpers_without_config_return_defaults():
    provider = make_provider_with_dmarc(
        None,
        provider_id="dmarc_none",
        name="No DMARC Provider",
    )
    checker = DNSChecker("example.test", provider)

    assert checker._effective_required_rua() == []
    assert checker._rua_required([]) is False
    assert checker._effective_required_ruf() == []
    assert checker._ruf_required([]) is False
