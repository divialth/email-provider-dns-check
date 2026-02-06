from provider_check.checker import DNSChecker
from provider_check.provider_config import MXRecord
from provider_check.status import Status

from tests.checker_mx_support import make_mx_config, make_provider_with_mx
from tests.support import FakeResolver


def test_mx_optional_priority_mismatch_warns_with_string_records():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=10)],
        ),
        provider_id="mx_optional_mismatch",
        name="MX Optional Mismatch Provider",
    )
    resolver = FakeResolver(mx={"example.test": ["mx2.example.test."]})
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.WARN
    assert result.message == "Optional MX records missing"
    assert "mismatched" in result.details


def test_mx_optional_missing_warns():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=20)],
        ),
        provider_id="mx_optional",
        name="MX Optional Provider",
    )
    resolver = FakeResolver(mx={"example.test": [("mx1.example.test.", 10)]})
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.WARN
    assert result.message == "Optional MX records missing"
    assert result.optional is True


def test_mx_optional_present_passes():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.", priority=20)],
        ),
        provider_id="mx_optional",
        name="MX Optional Provider",
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver)

    result = checker.check_mx_optional()

    assert result.status is Status.PASS
    assert result.message == "Optional MX records present"
    assert result.optional is True


def test_mx_optional_no_records_passes():
    provider = make_provider_with_mx(
        make_mx_config(required=[MXRecord(host="mx1.example.test.")]),
        provider_id="mx_optional",
        name="MX Optional Provider",
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    result = checker.check_mx_optional()

    assert result.status is Status.PASS
    assert result.message == "No optional MX records required"
    assert result.optional is True


def test_run_checks_includes_optional_mx():
    provider = make_provider_with_mx(
        make_mx_config(
            required=[MXRecord(host="mx1.example.test.")],
            optional=[MXRecord(host="mx2.example.test.")],
        ),
        provider_id="mx_optional",
        name="MX Optional Provider",
    )
    resolver = FakeResolver(
        mx={"example.test": [("mx1.example.test.", 10), ("mx2.example.test.", 20)]}
    )
    checker = DNSChecker("example.test", provider, resolver=resolver)

    results = checker.run_checks()

    assert any(result.record_type == "MX" and result.optional for result in results)
