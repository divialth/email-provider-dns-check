from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker_dmarc_support import make_dmarc_config, make_provider_with_dmarc
from tests.support import FakeResolver


def test_dmarc_optional_rua_allows_unexpected_rua():
    provider = make_provider_with_dmarc(
        make_dmarc_config(rua_required=False),
        provider_id="dmarc_optional",
        name="DMARC Optional Provider",
    )
    domain = "example.net"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:different@example.net"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_required_rua_and_tags():
    provider = make_provider_with_dmarc(
        make_dmarc_config(
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s", "aspf": "s"},
        ),
        provider_id="dmarc_required",
        name="DMARC Required Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:agg@example.test;adkim=s;aspf=s"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dmarc_result = next(r for r in results if r.record_type == "DMARC")
    assert dmarc_result.status is Status.PASS


def test_dmarc_missing_required_rua_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test"], required_tags={"adkim": "s"}),
        provider_id="dmarc_required",
        name="DMARC Required Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:other@example.test;adkim=s"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    dmarc_result = next(r for r in results if r.record_type == "DMARC")
    assert dmarc_result.status is Status.FAIL


def test_dmarc_required_tag_overrides_merge():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_tags={"adkim": "s", "aspf": "s"}),
        provider_id="dmarc_override_tags",
        name="DMARC Override Tags Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;adkim=r;aspf=s;pct=50;sp=reject"]}
    )

    checker = DNSChecker(
        "example.test",
        provider,
        resolver=resolver,
        strict=False,
        dmarc_required_tags={"adkim": "r", "pct": "50", "sp": "reject"},
    )
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_override_required_tag_missing_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(),
        provider_id="dmarc_override_tag_missing",
        name="DMARC Override Tag Missing Provider",
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=reject"]})

    checker = DNSChecker(
        "example.test",
        provider,
        resolver=resolver,
        strict=False,
        dmarc_required_tags={"sp": "reject"},
    )
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_rua_size_suffix_required_rejects_missing():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test!10m"]),
        provider_id="dmarc_rua_size_required",
        name="DMARC RUA Size Required Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=mailto:agg@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_rua_non_mailto_fails_when_required():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test"]),
        provider_id="dmarc_rua_non_mailto",
        name="DMARC RUA Non-Mailto Provider",
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=https://example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_required_ruf_passes():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;ruf=mailto:forensic@example.test"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_missing_required_ruf_fails():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;ruf=mailto:other@example.test"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_missing_ruf_fails_when_required():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject"]})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_rua_optional_allows_missing_rua():
    provider = make_provider_with_dmarc(
        make_dmarc_config(rua_required=False),
        provider_id="dmarc_optional",
        name="DMARC Optional Provider",
    )
    domain = "example.com"
    resolver = FakeResolver(txt={f"_dmarc.{domain}": ["v=DMARC1; p=reject"]})

    checker = DNSChecker(domain, provider, resolver=resolver)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_records_missing_requirements_fail():
    provider = make_provider_with_dmarc(
        make_dmarc_config(
            required_rua=["mailto:agg@example.test"],
            required_tags={"adkim": "s"},
        ),
        provider_id="dmarc_required",
        name="DMARC Required Provider",
    )
    resolver = FakeResolver(
        txt={
            "_dmarc.example.test": [
                "v=DMARC2;p=reject;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=none;rua=mailto:agg@example.test;adkim=s",
                "v=DMARC1;p=reject",
                "v=DMARC1;p=reject;rua=mailto:agg@example.test",
            ]
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_rua_override_replaces_required_rua():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_rua=["mailto:agg@example.test"]),
        provider_id="dmarc_override",
        name="DMARC Override Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:override@example.test"]}
    )

    checker = DNSChecker(
        domain,
        provider,
        resolver=resolver,
        strict=False,
        dmarc_rua_mailto=["override@example.test"],
    )
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_ruf_override_replaces_required_ruf():
    provider = make_provider_with_dmarc(
        make_dmarc_config(required_ruf=["mailto:forensic@example.test"]),
        provider_id="dmarc_override_ruf",
        name="DMARC Override RUF Provider",
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;ruf=mailto:override@example.test"]}
    )

    checker = DNSChecker(
        domain,
        provider,
        resolver=resolver,
        strict=False,
        dmarc_ruf_mailto=["override@example.test"],
    )
    result = checker.check_dmarc()

    assert result.status is Status.PASS
