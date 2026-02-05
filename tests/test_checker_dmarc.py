import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import DMARCConfig, ProviderConfig
from provider_check.status import Status

from tests.support import FakeResolver


def test_dmarc_optional_rua_allows_unexpected_rua():
    provider = ProviderConfig(
        provider_id="dmarc_optional",
        name="DMARC Optional Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
            rua_required=False,
        ),
    )
    domain = "example.net"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;rua=mailto:different@example.net"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_required_rua_and_tags():
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={"adkim": "s", "aspf": "s"},
        ),
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
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={"adkim": "s"},
        ),
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
    provider = ProviderConfig(
        provider_id="dmarc_override_tags",
        name="DMARC Override Tags Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={"adkim": "s", "aspf": "s"},
        ),
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
    provider = ProviderConfig(
        provider_id="dmarc_override_tag_missing",
        name="DMARC Override Tag Missing Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
        ),
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


def test_dmarc_rua_size_suffix_matches_required():
    provider = ProviderConfig(
        provider_id="dmarc_rua_size",
        name="DMARC RUA Size Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={},
        ),
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=mailto:agg@example.test!10m"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_rua_size_suffix_required_rejects_missing():
    provider = ProviderConfig(
        provider_id="dmarc_rua_size_required",
        name="DMARC RUA Size Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test!10m"],
            required_ruf=[],
            required_tags={},
        ),
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=mailto:agg@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_rua_non_mailto_fails_when_required():
    provider = ProviderConfig(
        provider_id="dmarc_rua_non_mailto",
        name="DMARC RUA Non-Mailto Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={},
        ),
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;rua=https://example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_rua_extra_entry_fails():
    provider = ProviderConfig(
        provider_id="dmarc_strict_rua_extra",
        name="DMARC Strict RUA Extra Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={},
        ),
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


def test_dmarc_required_ruf_passes():
    provider = ProviderConfig(
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;ruf=mailto:forensic@example.test"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_missing_required_ruf_fails():
    provider = ProviderConfig(
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    domain = "example.test"
    resolver = FakeResolver(
        txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject;ruf=mailto:other@example.test"]}
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_missing_ruf_fails_when_required():
    provider = ProviderConfig(
        provider_id="dmarc_required_ruf",
        name="DMARC Required RUF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    domain = "example.test"
    resolver = FakeResolver(txt={f"_dmarc.{domain}": ["v=DMARC1;p=reject"]})

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_requires_config():
    provider = ProviderConfig(
        provider_id="dmarc_none",
        name="No DMARC Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider, resolver=FakeResolver())

    with pytest.raises(ValueError):
        checker.check_dmarc()


def test_dmarc_rua_optional_allows_missing_rua():
    provider = ProviderConfig(
        provider_id="dmarc_optional",
        name="DMARC Optional Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
            rua_required=False,
        ),
    )
    domain = "example.com"
    resolver = FakeResolver(txt={f"_dmarc.{domain}": ["v=DMARC1; p=reject"]})

    checker = DNSChecker(domain, provider, resolver=resolver)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_lookup_error_returns_unknown():
    class FailingResolver(FakeResolver):
        def get_txt(self, domain: str):
            raise DnsLookupError("TXT", domain, RuntimeError("timeout"))

    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
        ),
    )
    checker = DNSChecker("example.test", provider, resolver=FailingResolver())

    result = checker.check_dmarc()

    assert result.status is Status.UNKNOWN


def test_dmarc_strict_mismatch_fails():
    provider = ProviderConfig(
        provider_id="dmarc_strict",
        name="DMARC Strict Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
        ),
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=none;rua=mailto:x"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_requires_ruf_matches():
    provider = ProviderConfig(
        provider_id="dmarc_strict_ruf",
        name="DMARC Strict RUF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;ruf=mailto:forensic@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.PASS


def test_dmarc_strict_missing_ruf_fails():
    provider = ProviderConfig(
        provider_id="dmarc_strict_ruf_missing",
        name="DMARC Strict RUF Missing Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    resolver = FakeResolver(txt={"_dmarc.example.test": ["v=DMARC1;p=reject"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_strict_ruf_mismatch_fails():
    provider = ProviderConfig(
        provider_id="dmarc_strict_ruf_mismatch",
        name="DMARC Strict RUF Mismatch Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
    )
    resolver = FakeResolver(
        txt={"_dmarc.example.test": ["v=DMARC1;p=reject;ruf=mailto:other@example.test"]}
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=True)
    result = checker.check_dmarc()

    assert result.status is Status.FAIL


def test_dmarc_records_missing_requirements_fail():
    provider = ProviderConfig(
        provider_id="dmarc_required",
        name="DMARC Required Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={"adkim": "s"},
        ),
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
    provider = ProviderConfig(
        provider_id="dmarc_override",
        name="DMARC Override Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={},
        ),
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
    provider = ProviderConfig(
        provider_id="dmarc_override_ruf",
        name="DMARC Override RUF Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=["mailto:forensic@example.test"],
            required_tags={},
        ),
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


def test_dmarc_rua_mailto_rejects_empty_values():
    provider = ProviderConfig(
        provider_id="dmarc_rua_invalid",
        name="DMARC Invalid RUA",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
        ),
    )

    with pytest.raises(ValueError, match="must not be empty"):
        DNSChecker("example.test", provider, dmarc_rua_mailto=[""])

    with pytest.raises(ValueError, match="must include an address"):
        DNSChecker("example.test", provider, dmarc_rua_mailto=["mailto:"])

    with pytest.raises(ValueError, match="must not be empty"):
        DNSChecker("example.test", provider, dmarc_ruf_mailto=[""])

    with pytest.raises(ValueError, match="must include an address"):
        DNSChecker("example.test", provider, dmarc_ruf_mailto=["mailto:"])


def test_dmarc_helpers_without_config_return_defaults():
    provider = ProviderConfig(
        provider_id="dmarc_none",
        name="No DMARC Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DNSChecker("example.test", provider)

    assert checker._effective_required_rua() == []
    assert checker._rua_required([]) is False
    assert checker._effective_required_ruf() == []
    assert checker._ruf_required([]) is False


def test_dmarc_strict_filters_invalid_records():
    provider = ProviderConfig(
        provider_id="dmarc_strict_filters",
        name="DMARC Strict Filters",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:agg@example.test"],
            required_ruf=[],
            required_tags={"adkim": "s"},
        ),
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
