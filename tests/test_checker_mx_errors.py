import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import MXRecord
from provider_check.status import Status

from tests.checker_mx_support import make_mx_config, make_provider_with_mx
from tests.support import FakeResolver


@pytest.mark.parametrize("method_name", ["check_mx", "check_mx_optional"])
def test_mx_checks_require_config(method_name: str):
    provider = make_provider_with_mx(
        None,
        provider_id="mx_optional",
        name="MX Optional Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="MX configuration not available for provider"):
        getattr(checker, method_name)()


@pytest.mark.parametrize(
    ("method_name", "optional"),
    [("check_mx", False), ("check_mx_optional", True)],
)
def test_mx_lookup_error_returns_unknown(method_name: str, optional: bool):
    class FailingResolver(FakeResolver):
        def get_mx(self, domain: str):
            raise DnsLookupError("MX", domain, RuntimeError("timeout"))

    provider = make_provider_with_mx(
        make_mx_config(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.")],
        ),
        provider_id="mx_provider",
        name="MX Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = getattr(checker, method_name)()

    assert result.status is Status.UNKNOWN
    assert result.message == "DNS lookup failed"
    assert result.optional is optional
