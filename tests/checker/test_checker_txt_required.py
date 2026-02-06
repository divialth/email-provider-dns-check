from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker.txt_support import make_provider_with_txt, make_txt_config
from tests.support import FakeResolver


def test_txt_required_values_pass():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one", "token=two"]}),
        provider_id="txt_required",
        name="TXT Required Provider",
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
    assert txt_result.message == "TXT records present"


def test_txt_missing_values_fail():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one", "token=two"]}),
        provider_id="txt_required",
        name="TXT Required Provider",
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
    assert txt_result.message == "TXT records missing required values"


def test_additional_txt_without_provider_config():
    provider = make_provider_with_txt(
        None,
        provider_id="txt_optional",
        name="TXT Optional Provider",
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
    assert txt_result.message == "TXT records present"


def test_additional_txt_verification_without_provider_config():
    provider = make_provider_with_txt(
        None,
        provider_id="txt_optional",
        name="TXT Optional Provider",
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
    assert txt_result.message == "TXT records present"


def test_txt_verification_required_warns_without_user_input():
    provider = make_provider_with_txt(
        make_txt_config(verification_required=True),
        provider_id="txt_user",
        name="TXT User Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.WARN
    assert txt_result.message == "TXT record required for domain verification"


def test_txt_verification_required_can_be_skipped():
    provider = make_provider_with_txt(
        make_txt_config(verification_required=True),
        provider_id="txt_user",
        name="TXT User Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={})

    checker = DNSChecker(
        domain, provider, resolver=resolver, strict=False, skip_txt_verification=True
    )
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.PASS
    assert txt_result.message == "No TXT records required"


def test_txt_normalizes_names():
    provider = make_provider_with_txt(
        None,
        provider_id="txt_normalize",
        name="TXT Normalize Provider",
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
    assert txt_result.message == "TXT records present"


def test_txt_missing_records_reports_missing_names():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one"], "_verify2": ["token=two"]}),
        provider_id="txt_required",
        name="TXT Required Provider",
    )
    resolver = FakeResolver(txt={})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.FAIL
    assert txt_result.message == "TXT records missing required values"
    assert "missing_names" in txt_result.details


def test_txt_missing_records_include_verification_required():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one"]}, verification_required=True),
        provider_id="txt_required",
        name="TXT Required Provider",
    )
    resolver = FakeResolver(txt={})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.FAIL
    assert txt_result.message == "TXT records missing required values"
    assert "verification_required" in txt_result.details


def test_txt_verification_warning_with_required_values():
    provider = make_provider_with_txt(
        make_txt_config(required={"_verify": ["token=one"]}, verification_required=True),
        provider_id="txt_required",
        name="TXT Required Provider",
    )
    resolver = FakeResolver(txt={"_verify.example.test": ["token=one"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    txt_result = next(r for r in results if r.record_type == "TXT")
    assert txt_result.status is Status.WARN
    assert txt_result.message == "TXT record required for domain verification"
