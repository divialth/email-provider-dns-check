from provider_check.checker import DNSChecker
from provider_check.status import Status

from tests.checker.spf_support import make_provider_with_spf, make_spf_config
from tests.support import FakeResolver


def test_spf_allowed_mechanisms_pass():
    provider = make_provider_with_spf(
        make_spf_config(
            optional_mechanisms=["a", "mx"],
        ),
        provider_id="spf_allowed",
        name="Allowed SPF Provider",
    )
    domain = "allowed.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a mx -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_unexpected_mechanism_warns_when_configured():
    provider = make_provider_with_spf(
        make_spf_config(required_mechanisms=["a"]),
        provider_id="spf_warn",
        name="Warn SPF Provider",
    )
    domain = "warn.example"
    resolver = FakeResolver(
        txt={
            domain: ["v=spf1 a ptr -all"],
        }
    )

    checker = DNSChecker(domain, provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.WARN
    assert "ptr" in spf_result.details.get("extras", [])


def test_spf_requires_mechanism_base_pass():
    provider = make_provider_with_spf(
        make_spf_config(required_mechanisms=["a"]),
        provider_id="spf_required_mech",
        name="Required Mechanism Provider",
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 a -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_accepts_additional_ip4_ip6():
    provider = make_provider_with_spf(
        make_spf_config(),
        provider_id="spf_ip",
        name="IP SPF Provider",
    )
    resolver = FakeResolver(
        txt={
            "example.test": [
                "v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 -all",
            ]
        }
    )

    checker = DNSChecker(
        "example.test",
        provider,
        resolver=resolver,
        strict=False,
        additional_spf_ip4=["192.0.2.1"],
        additional_spf_ip6=["2001:db8::1"],
    )
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_required_and_allowed_mechanisms_cover_base():
    provider = make_provider_with_spf(
        make_spf_config(required_mechanisms=["a"], optional_mechanisms=["mx"]),
        provider_id="spf_required_allowed",
        name="Required/Allowed SPF Provider",
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 a mx -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_required_mechanism_with_qualifier_passes():
    provider = make_provider_with_spf(
        make_spf_config(required_mechanisms=["-ptr"]),
        provider_id="spf_required_exact",
        name="Required Exact SPF Provider",
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 -ptr -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS


def test_spf_allowed_mechanism_with_qualifier_passes():
    provider = make_provider_with_spf(
        make_spf_config(optional_mechanisms=["-ptr"]),
        provider_id="spf_allowed_exact",
        name="Allowed Exact SPF Provider",
    )
    resolver = FakeResolver(txt={"example.test": ["v=spf1 -ptr -all"]})

    checker = DNSChecker("example.test", provider, resolver=resolver, strict=False)
    results = checker.run_checks()

    spf_result = next(r for r in results if r.record_type == "SPF")
    assert spf_result.status is Status.PASS
