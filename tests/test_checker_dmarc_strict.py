from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker_dmarc_support import make_dmarc_config, make_provider_with_dmarc
from tests.support import FakeResolver


def test_dmarc_rua_size_suffix_matches_required():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test"]),
        provider_id="dmarc_rua_size",
        name="DMARC RUA Size Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=mailto:agg@example.test!10m"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_strict_rua_extra_entry_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test"]),
        provider_id="dmarc_strict_rua_extra",
        name="DMARC Strict RUA Extra Provider",
    )
    resolver = FakeResolver(
        txt={
            "_dmarc.example.test": [
                "v=DMARC1;p=reject;rua=mailto:agg@example.test,mailto:extra@example.test"
            ]
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_mismatch_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(),
        provider_id="dmarc_strict",
        name="DMARC Strict Provider",
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=none;rua=mailto:x"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_requires_ruf_matches():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_strict_ruf",
        name="DMARC Strict RUF Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;ruf=mailto:forensic@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_strict_missing_ruf_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_strict_ruf_missing",
        name="DMARC Strict RUF Missing Provider",
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=reject"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_ruf_mismatch_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_strict_ruf_mismatch",
        name="DMARC Strict RUF Mismatch Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;ruf=mailto:other@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_filters_invalid_records():
    provider = make_provider_with_dmarc(
        make_dmarc_config(
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s"},
        ),
        provider_id="dmarc_strict_filters",
        name="DMARC Strict Filters",
    )
    resolver = FakeResolver(
        txt={
            "_dmarc.example.test": [
                "v=DMARC2;p=reject;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=none;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=reject;adkim=s",
                "v=DMARC1;p=reject;rua=mailto:other@example.test;adkim=s",
                "v=DMARC1;p=reject;rua=mailto:agg@example.test",
                "v=DMARC1;p=reject;rua=mailto:agg@example.test;adkim=s;aspf=s",
            ]
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL
