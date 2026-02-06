from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker_spf_support import make_provider_with_spf, make_spf_config
from tests.support import FakeResolver


def test_spf_required_modifiers_missing_fails():
    provider = make_provider_with_spf(
        make_spf_config(required_modifiers={"redirect": "_spf.example.test"}),
        provider_id="spf_mod",
        name="Modifier SPF Provider",
    )
    domain = "mod.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.FAIL


def test_spf_optional_modifier_passes_when_present():
    provider = make_provider_with_spf(
        make_spf_config(optional_modifiers={"exp": "explain._spf.example.test"}),
        provider_id="spf_optional_modifier",
        name="Optional Modifier SPF Provider",
    )
    resolver = FakeResolver(
        txt={
            "example.test": ["v=spf1 exp=explain._spf.example.test -all"],
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_optional_modifier_unexpected_warns():
    provider = make_provider_with_spf(
        make_spf_config(optional_modifiers={"exp": "explain._spf.example.test"}),
        provider_id="spf_optional_modifier",
        name="Optional Modifier SPF Provider",
    )
    resolver = FakeResolver(
        txt={
            "example.test": ["v=spf1 exp=wrong.example.test redirect=_spf.example.test -all"],
        }
    )

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.WARN
    extras = spf_result.details.get("extras", [])
    assert "exp=wrong.example.test" in extras
    assert "redirect=_spf.example.test" in extras
