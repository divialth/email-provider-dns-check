from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import SRVRecord
from provider_check.status import Status

from tests.checker_srv_support import make_provider_with_srv, make_srv_config
from tests.support import FakeResolver


class FailingResolver(FakeResolver):
    def get_srv(self, name: str):
        raise DnsLookupError("SRV", name, RuntimeError("timeout"))


def test_srv_lookup_error_returns_unknown():
    provider = make_provider_with_srv(
        make_srv_config(
            required={
                "_sip._tls": [
                    SRVRecord(priority=100, weight=1, port=443, target="srv.primary.provider.test.")
                ]
            }
        )
    )
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_srv()

    assert result.status is Status.UNKNOWN
    assert result.message == "DNS lookup failed"
    assert result.optional is False


def test_srv_optional_lookup_error_returns_unknown():
    provider = make_provider_with_srv(
        make_srv_config(
            optional={
                "_autodiscover._tcp": [
                    SRVRecord(
                        priority=0,
                        weight=0,
                        port=443,
                        target="autodiscover.provider.test.",
                    )
                ]
            }
        )
    )
    checker = DNSChecker("example.com", provider, resolver=FailingResolver())

    result = checker.check_srv_optional()

    assert result.status is Status.UNKNOWN
    assert result.message == "DNS lookup failed"
    assert result.optional is True
