import pytest

from provider_check.provider_config import (
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    CNAMEConfig,
    SRVConfig,
    SRVRecord,
    TXTConfig,
    resolve_provider_config,
)


def test_resolve_provider_config_applies_variables_and_domain():
    provider = ProviderConfig(
        provider_id="var_provider",
        name="Variable Provider",
        version="1",
        mx=MXConfig(hosts=["{tenant}.mx.{region}.example.test."], priorities={}),
        spf=SPFConfig(
            required_includes=["spf.{tenant}.example.test"],
            strict_record="v=spf1 include:spf.{tenant}.example.test -all",
            required_mechanisms=["exists:%{i}.spf.{tenant}.example.test"],
            allowed_mechanisms=[],
            required_modifiers={"redirect": "_spf.{tenant}.example.test"},
        ),
        dkim=DKIMConfig(
            selectors=["sel-{tenant}"],
            record_type="cname",
            target_template="{selector}._domainkey.{tenant}.example.test.",
            txt_values={},
        ),
        cname=CNAMEConfig(
            records={"sip": "sip.{tenant}.example.test.", "lyncdiscover": "webdir.{tenant}."}
        ),
        srv=SRVConfig(
            records={
                "_sip._tls": [
                    SRVRecord(
                        priority=100,
                        weight=1,
                        port=443,
                        target="sipdir.{tenant}.example.test.",
                    )
                ]
            }
        ),
        txt=TXTConfig(
            required={"_verify.{domain}": ["token-{tenant}"]},
            verification_required=False,
        ),
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=["mailto:dmarc@{domain}"],
            required_ruf=["mailto:forensic@{domain}"],
            required_tags={"pct": "100"},
        ),
        variables={
            "tenant": ProviderVariable(name="tenant", required=True),
            "region": ProviderVariable(name="region", default="us"),
        },
    )

    resolved = resolve_provider_config(
        provider,
        {"tenant": "contoso"},
        domain="example.test",
    )

    assert resolved.mx.hosts == ["contoso.mx.us.example.test."]
    assert resolved.spf.required_includes == ["spf.contoso.example.test"]
    assert resolved.spf.strict_record == "v=spf1 include:spf.contoso.example.test -all"
    assert resolved.spf.required_modifiers["redirect"] == "_spf.contoso.example.test"
    assert resolved.dkim.selectors == ["sel-contoso"]
    assert resolved.dkim.target_template == "{selector}._domainkey.contoso.example.test."
    assert resolved.cname.records == {
        "sip": "sip.contoso.example.test.",
        "lyncdiscover": "webdir.contoso.",
    }
    assert resolved.srv.records["_sip._tls"][0].target == "sipdir.contoso.example.test."
    assert resolved.txt.required == {"_verify.example.test": ["token-contoso"]}
    assert resolved.dmarc.required_rua == ["mailto:dmarc@example.test"]
    assert resolved.dmarc.required_ruf == ["mailto:forensic@example.test"]


def test_resolve_provider_config_missing_required_variable():
    provider = ProviderConfig(
        provider_id="var_provider",
        name="Variable Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        variables={"tenant": ProviderVariable(name="tenant", required=True)},
    )

    with pytest.raises(ValueError, match="Missing required provider variable"):
        resolve_provider_config(provider, {})


def test_resolve_provider_config_unknown_variable():
    provider = ProviderConfig(
        provider_id="var_provider",
        name="Variable Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )

    with pytest.raises(ValueError, match="Unknown provider variable"):
        resolve_provider_config(provider, {"unknown": "value"})


def test_resolve_provider_config_rejects_variables_for_provider_without_vars():
    provider = ProviderConfig(
        provider_id="no_vars",
        name="No Vars",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )

    with pytest.raises(ValueError, match="does not accept variables"):
        resolve_provider_config(provider, {"token": "value"})


def test_resolve_provider_config_returns_original_when_no_values():
    provider = ProviderConfig(
        provider_id="optional_vars",
        name="Optional Vars",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        variables={"token": ProviderVariable(name="token", required=False)},
    )

    resolved = resolve_provider_config(provider, {})

    assert resolved is provider


def test_resolve_provider_config_formats_none_values():
    provider = ProviderConfig(
        provider_id="none_values",
        name="None Values",
        version="1",
        mx=None,
        spf=SPFConfig(
            required_includes=["include.{token}.example.test"],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=None,
        txt=None,
        dmarc=None,
        variables={"token": ProviderVariable(name="token", required=False)},
    )

    resolved = resolve_provider_config(provider, {"token": "value"})

    assert resolved.spf.strict_record is None
