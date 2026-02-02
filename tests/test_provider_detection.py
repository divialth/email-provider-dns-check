import provider_check.detection as detection
from provider_check.detection import detect_providers
from provider_check.provider_config import (
    CNAMEConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
)
from tests.support import FakeResolver


def _provider(provider_id, mx_hosts, variables=None):
    return ProviderConfig(
        provider_id=provider_id,
        name=f"{provider_id} Provider",
        version="1",
        mx=MXConfig(hosts=mx_hosts, priorities={}),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        variables=variables or {},
    )


def test_detect_providers_selects_best_match(monkeypatch):
    provider_alpha = _provider("alpha", ["mx.alpha.test."])
    provider_beta = _provider("beta", ["mx.beta.test."])
    monkeypatch.setattr(detection, "list_providers", lambda: [provider_alpha, provider_beta])
    resolver = FakeResolver(mx={"example.com": [("mx.alpha.test.", 10)]})

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "PASS"
    assert report.selected is not None
    assert report.selected.provider_id == "alpha"
    assert report.candidates[0].provider_id == "alpha"


def test_detect_providers_marks_tie_as_ambiguous(monkeypatch):
    provider_alpha = _provider("alpha", ["mx.shared.test."])
    provider_beta = _provider("beta", ["mx.shared.test."])
    monkeypatch.setattr(detection, "list_providers", lambda: [provider_alpha, provider_beta])
    resolver = FakeResolver(mx={"example.com": [("mx.shared.test.", 10)]})

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "UNKNOWN"
    assert report.selected is None
    assert report.ambiguous is True
    assert {candidate.provider_id for candidate in report.candidates} == {"alpha", "beta"}


def test_detect_providers_breaks_ratio_ties_by_score(monkeypatch):
    provider_alpha = _provider("alpha", ["mx.shared.test."])
    provider_beta = ProviderConfig(
        provider_id="beta",
        name="beta Provider",
        version="1",
        mx=MXConfig(hosts=["mx.shared.test."], priorities={}),
        spf=SPFConfig(
            required_includes=["example.test"],
            strict_record="v=spf1 include:example.test -all",
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
        variables={},
    )
    monkeypatch.setattr(detection, "list_providers", lambda: [provider_alpha, provider_beta])
    resolver = FakeResolver(
        mx={"example.com": [("mx.shared.test.", 10)]},
        txt={"example.com": ["v=spf1 include:example.test -all"]},
    )

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "PASS"
    assert report.ambiguous is False
    assert report.selected is not None
    assert report.selected.provider_id == "beta"


def test_detect_providers_breaks_ties_with_optional_bonus(monkeypatch):
    provider_alpha = ProviderConfig(
        provider_id="alpha",
        name="alpha Provider",
        version="1",
        mx=MXConfig(hosts=["mx.shared.test."], priorities={}),
        spf=None,
        dkim=None,
        cname=CNAMEConfig(records={}, records_optional={"autoconfig": "auto.alpha.test."}),
        srv=None,
        txt=None,
        dmarc=None,
        variables={},
    )
    provider_beta = ProviderConfig(
        provider_id="beta",
        name="beta Provider",
        version="1",
        mx=MXConfig(hosts=["mx.shared.test."], priorities={}),
        spf=None,
        dkim=None,
        cname=CNAMEConfig(records={}, records_optional={"autoconfig": "auto.beta.test."}),
        srv=None,
        txt=None,
        dmarc=None,
        variables={},
    )
    monkeypatch.setattr(detection, "list_providers", lambda: [provider_alpha, provider_beta])
    resolver = FakeResolver(
        mx={"example.com": [("mx.shared.test.", 10)]},
        cname={"autoconfig.example.com": "auto.alpha.test."},
    )

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "PASS"
    assert report.selected is not None
    assert report.selected.provider_id == "alpha"
    assert report.ambiguous is False


def test_detect_providers_infers_variables(monkeypatch):
    variables = {
        "custom_domain_dashes": ProviderVariable(name="custom_domain_dashes", required=True)
    }
    provider = _provider(
        "templated",
        ["{custom_domain_dashes}.mail.example.test."],
        variables=variables,
    )
    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    resolver = FakeResolver(mx={"example.com": [("example-com.mail.example.test.", 10)]})

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "PASS"
    assert report.selected is not None
    assert report.selected.inferred_variables["custom_domain_dashes"] == "example-com"


def test_detect_providers_skips_missing_required_variables(monkeypatch):
    variables = {"tenant": ProviderVariable(name="tenant", required=True)}
    provider = _provider("missing-vars", ["{tenant}.mail.example.test."], variables=variables)
    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    resolver = FakeResolver(mx={"example.com": [("mx.other.test.", 10)]})

    report = detect_providers("example.com", resolver=resolver, top_n=3)

    assert report.status == "UNKNOWN"
    assert report.selected is None
    assert report.candidates == []
