from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.status import Status

from tests.checker.txt_support import make_provider_with_txt, make_txt_config
from tests.support import FakeResolver


class FailingResolver(FakeResolver):
    def get_txt(self, domain: str):
        raise DnsLookupError("TXT", domain, RuntimeError("timeout"))


def test_txt_lookup_error_returns_unknown():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one"]}),
        provider_id="txt_required",
        name="TXT Required Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_txt()

    assert result.status is Status.UNKNOWN
    assert result.message == "DNS lookup failed"
    assert result.optional is False


def test_txt_optional_lookup_error_returns_unknown():
    provider = make_provider_with_txt(
        make_txt_config(
            optional={"_optional": ["token=two"]},
        ),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_txt_optional()

    assert result.status is Status.UNKNOWN
    assert result.message == "DNS lookup failed"
    assert result.optional is True
