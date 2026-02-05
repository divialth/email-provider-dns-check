import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import ProviderConfig, TXTConfig
from provider_check.status import Status

from tests.support import FakeResolver


def test_txt_required_values_pass():
    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one", "token=two"]}),
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"_verify.{domain}": ["token=one", "token=two"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS


def test_txt_missing_values_fail():
    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one", "token=two"]}),
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"_verify.{domain}": ["token=one"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.FAIL


def test_additional_txt_without_provider_config():
    provider = ProviderConfig(
        provider_id="txt_optional",
        name="TXT Optional Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"custom.{domain}": ["custom=value"],
        }
    )

    checker = DNSChecker(
        domain,
        provider,
        resolver=resolver,
        strict=False,
        additional_txt={"custom": ["custom=value"]},
    )
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS


def test_additional_txt_verification_without_provider_config():
    provider = ProviderConfig(
        provider_id="txt_optional",
        name="TXT Optional Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"verify.{domain}": ["verify=value"],
        }
    )

    checker = DNSChecker(
        domain,
        provider,
        resolver=resolver,
        strict=False,
        additional_txt_verification={"verify": ["verify=value"]},
    )
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS


def test_txt_verification_required_warns_without_user_input():
    provider = ProviderConfig(
        provider_id="txt_user",
        name="TXT User Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={}, verification_required=True),
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(txt={})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.WARN


def test_txt_verification_required_can_be_skipped():
    provider = ProviderConfig(
        provider_id="txt_user",
        name="TXT User Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={}, verification_required=True),
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(txt={})

    checker = DNSChecker(
        domain, provider, resolver=resolver, strict=False, skip_txt_verification=True
    )
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS


def test_txt_normalizes_names():
    provider = ProviderConfig(
        provider_id="txt_normalize",
        name="TXT Normalize Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            domain: ["token"],
            f"verify.{domain}": ["token"],
            "full": ["token"],
            f"host.{domain}": ["token"],
            f"simple.{domain}": ["token"],
        }
    )

    checker = DNSChecker(
        domain,
        provider,
        resolver=resolver,
        strict=False,
        additional_txt={
            "@": ["token"],
            "verify.{domain}": ["token"],
            "full.": ["token"],
            f"host.{domain}": ["token"],
            "simple": ["token"],
        },
    )
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS


def test_txt_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, domain: str):
            raise DnsLookupError("TXT", domain, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one"]}),
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.UNKNOWN


def test_txt_missing_records_reports_missing_names():
    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one"], "_verify2": ["token=two"]}),
        dmarc=None,
    )
    resolver = FakeResolver(txt={})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.FAIL
    assert "missing_names" in txt_result.details


def test_txt_missing_records_include_verification_required():
    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one"]}, verification_required=True),
        dmarc=None,
    )
    resolver = FakeResolver(txt={})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.FAIL
    assert "verification_required" in txt_result.details


def test_txt_verification_warning_with_required_values():
    provider = ProviderConfig(
        provider_id="txt_required",
        name="TXT Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=TXTConfig(required={"_verify": ["token=one"]}, verification_required=True),
        dmarc=None,
    )
    resolver = FakeResolver(txt={"_verify.example.test": ["token=one"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.WARN
