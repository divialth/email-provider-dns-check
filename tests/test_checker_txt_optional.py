import pytest

from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker_txt_support import make_provider_with_txt, make_txt_config
from tests.support import FakeResolver


def test_txt_optional_missing_warns():
    provider = make_provider_with_txt(
        make_txt_config(optional={"_verify": ["token=one"]}),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_txt_optional()

    assert result.status is Status.WARN
    assert result.message == "Optional TXT records missing"
    assert result.optional is True
    assert result.details["missing"]["_verify"] == ["token=one"]


def test_txt_optional_missing_values_warns():
    provider = make_provider_with_txt(
        make_txt_config(optional={"_verify": ["token=one", "token=two"]}),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={f"_verify.{domain}": ["token=one"]})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_txt_optional()

    assert result.status is Status.WARN
    assert result.message == "Optional TXT records missing"
    assert result.optional is True
    assert result.details["missing"]["_verify"] == ["token=two"]


def test_txt_optional_present_passes():
    provider = make_provider_with_txt(
        make_txt_config(optional={"_verify": ["token=one"]}),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={f"_verify.{domain}": ["token=one"]})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_txt_optional()

    assert result.status is Status.PASS
    assert result.message == "Optional TXT records present"
    assert result.optional is True


def test_txt_optional_no_records_passes():
    provider = make_provider_with_txt(
        make_txt_config(),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver(), strict=False)

    result = checker.check_txt_optional()

    assert result.status is Status.PASS
    assert result.message == "No optional TXT records required"
    assert result.optional is True


def test_txt_optional_requires_config():
    provider = make_provider_with_txt(
        None,
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError, match="TXT configuration not available"):
        checker.check_txt_optional()


def test_run_checks_includes_optional_txt():
    provider = make_provider_with_txt(
        make_txt_config(
            required={"_verify": ["token=one"]},
            optional={"_optional": ["token=two"]},
        ),
        provider_id="txt_optional",
        name="TXT Optional Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={
            f"_verify.{domain}": ["token=one"],
            f"_optional.{domain}": ["token=two"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    assert any(result.record_type == "TXT" and result.optional for result in results)
