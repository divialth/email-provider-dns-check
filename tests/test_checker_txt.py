from provider_check.checker import DNSChecker
from provider_check.provider_config import ProviderConfig, TXTConfig

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
    assert txt_result.status == "PASS"


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
    assert txt_result.status == "FAIL"


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
    assert txt_result.status == "PASS"


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
    assert txt_result.status == "PASS"


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
    assert txt_result.status == "WARN"


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
    assert txt_result.status == "PASS"
