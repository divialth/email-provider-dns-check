import logging

from provider_check.checker import DNSChecker
from provider_check.provider_config import MXConfig, MXRecord, ProviderConfig
from provider_check.status import Status

from tests.support import FakeResolver


def _provider_with_mx() -> ProviderConfig:
    return ProviderConfig(
        provider_id="dummy_provider",
        name="Dummy Provider",
        version="1",
        mx=MXConfig(required=[MXRecord(host="mx1.example.test.")], optional=[]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )


def _provider_without_records() -> ProviderConfig:
    return ProviderConfig(
        provider_id="empty_provider",
        name="Empty Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )


def test_checker_logs_info_and_debug_for_pass(caplog):
    provider = _provider_with_mx()
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)

    caplog.set_level(logging.DEBUG, logger="provider_check.checker")
    checker.run_checks()

    assert "Running DNS checks for example.test" in caplog.text
    assert "MX: PASS" in caplog.text
    assert "MX details:" in caplog.text


def test_checker_logs_info_for_fail(caplog):
    provider = _provider_with_mx()
    resolver = FakeResolver()
    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)

    caplog.set_level(logging.INFO, logger="provider_check.checker")
    checker.run_checks()

    assert "MX: FAIL" in caplog.text


def test_checker_logs_when_no_checks_enabled(caplog):
    provider = _provider_without_records()
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    caplog.set_level(logging.INFO, logger="provider_check.checker")
    results = checker.run_checks()

    assert results == []
    assert "No checks enabled for example.test" in caplog.text
