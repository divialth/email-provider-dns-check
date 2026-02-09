"""Tests for deprecated/forbidden CNAME and TXT checks."""

from __future__ import annotations

import pytest

from provider_check.checker import DNSChecker
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import (
    CNAMEMatchRule,
    CNAMEConfig,
    ProviderConfig,
    TXTConfig,
    TXTSettings,
    ValuesMatchRule,
)
from provider_check.status import Status

from tests.support import FakeResolver


def _provider(*, cname: CNAMEConfig | None = None, txt: TXTConfig | None = None) -> ProviderConfig:
    return ProviderConfig(
        provider_id="negative-cname-txt",
        name="Negative CNAME TXT",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        cname=cname,
        txt=txt,
        dmarc=None,
    )


def test_cname_deprecated_exact_and_forbidden_any() -> None:
    provider = _provider(
        cname=CNAMEConfig(
            required={},
            deprecated={"legacy": CNAMEMatchRule(match="exact", target="legacy.provider.test.")},
            forbidden={"blocked": CNAMEMatchRule(match="any", target=None)},
        )
    )
    resolver = FakeResolver(
        cname={
            "legacy.example.com": "legacy.provider.test.",
            "blocked.example.com": "blocked.provider.test.",
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_cname_deprecated()
    forbidden_result = checker.check_cname_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_cname_forbidden_passes_when_missing() -> None:
    provider = _provider(
        cname=CNAMEConfig(
            required={},
            forbidden={"legacy": CNAMEMatchRule(match="exact", target="legacy.provider.test.")},
        )
    )

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_cname_forbidden()

    assert result.status is Status.PASS
    assert result.scope == "forbidden"


def test_cname_deprecated_no_rules_passes() -> None:
    provider = _provider(cname=CNAMEConfig(required={}))

    result = DNSChecker("example.com", provider, resolver=FakeResolver()).check_cname_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_cname_deprecated_exact_without_target_is_ignored() -> None:
    provider = _provider(
        cname=CNAMEConfig(
            required={},
            deprecated={"legacy": CNAMEMatchRule(match="exact", target=None)},
        )
    )
    resolver = FakeResolver(cname={"legacy.example.com": "legacy.provider.test."})

    result = DNSChecker("example.com", provider, resolver=resolver).check_cname_deprecated()

    assert result.status is Status.PASS
    assert result.scope == "deprecated"


def test_cname_deprecated_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_cname(self, name: str):
            raise DnsLookupError("CNAME", name, RuntimeError("timeout"))

    provider = _provider(
        cname=CNAMEConfig(
            required={},
            deprecated={"legacy": CNAMEMatchRule(match="any", target=None)},
        )
    )

    result = DNSChecker(
        "example.com", provider, resolver=FailingResolver()
    ).check_cname_deprecated()

    assert result.status is Status.UNKNOWN
    assert result.scope == "deprecated"


def test_cname_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(cname=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="CNAME configuration not available"):
        checker.check_cname_deprecated()
    with pytest.raises(ValueError, match="CNAME configuration not available"):
        checker.check_cname_forbidden()


def test_txt_negative_checks() -> None:
    provider = _provider(
        txt=TXTConfig(
            required={},
            deprecated={"_legacy": ValuesMatchRule(match="exact", values=["legacy=true"])},
            forbidden={"_blocked": ValuesMatchRule(match="any", values=[])},
            settings=TXTSettings(verification_required=False),
        )
    )
    resolver = FakeResolver(
        txt={
            "_legacy.example.com": ["legacy=true"],
            "_blocked.example.com": ["blocked=true"],
        }
    )
    checker = DNSChecker("example.com", provider, resolver=resolver)

    deprecated_result = checker.check_txt_deprecated()
    forbidden_result = checker.check_txt_forbidden()

    assert deprecated_result.status is Status.WARN
    assert deprecated_result.scope == "deprecated"
    assert forbidden_result.status is Status.FAIL
    assert forbidden_result.scope == "forbidden"


def test_txt_negative_no_rules_and_no_matches_pass() -> None:
    provider = _provider(
        txt=TXTConfig(
            required={},
            forbidden={"_blocked": ValuesMatchRule(match="exact", values=["blocked=true"])},
            settings=TXTSettings(verification_required=False),
        )
    )
    resolver = FakeResolver(txt={"_blocked.example.com": ["safe=true"]})
    checker = DNSChecker("example.com", provider, resolver=resolver)

    no_rules_result = checker.check_txt_deprecated()
    no_matches_result = checker.check_txt_forbidden()

    assert no_rules_result.status is Status.PASS
    assert no_rules_result.scope == "deprecated"
    assert no_matches_result.status is Status.PASS
    assert no_matches_result.scope == "forbidden"


def test_txt_forbidden_lookup_error_unknown() -> None:
    class FailingResolver(FakeResolver):
        def get_txt(self, name: str):
            raise DnsLookupError("TXT", name, RuntimeError("timeout"))

    provider = _provider(
        txt=TXTConfig(
            required={},
            forbidden={"_blocked": ValuesMatchRule(match="any", values=[])},
            settings=TXTSettings(verification_required=False),
        )
    )

    result = DNSChecker("example.com", provider, resolver=FailingResolver()).check_txt_forbidden()

    assert result.status is Status.UNKNOWN
    assert result.scope == "forbidden"


def test_txt_negative_requires_config() -> None:
    checker = DNSChecker("example.com", _provider(txt=None), resolver=FakeResolver())

    with pytest.raises(ValueError, match="TXT configuration not available"):
        checker.check_txt_deprecated()
    with pytest.raises(ValueError, match="TXT configuration not available"):
        checker.check_txt_forbidden()
