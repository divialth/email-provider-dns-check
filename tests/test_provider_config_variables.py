import pytest

from provider_check.provider_config import (
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    CAAConfig,
    CAARecord,
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
            records={"sip": "sip.{tenant}.example.test.", "discover": "webdir.{tenant}."},
            records_optional={"autoconfig": "auto.{tenant}.example.test."},
        ),
        caa=CAAConfig(
            records={"@": [CAARecord(flags=0, tag="issue", value="ca.{tenant}.example.test")]},
            records_optional={
                "mail.{domain}": [CAARecord(flags=0, tag="iodef", value="mailto:security@{domain}")]
            },
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
            },
            records_optional={
                "_autodiscover._tcp": [
                    SRVRecord(
                        priority=10,
                        weight=5,
                        port=443,
                        target="auto.{tenant}.example.test.",
                    )
                ]
            },
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
        {"tenant": "tenant-a"},
        domain="example.test",
    )

    assert resolved.mx.hosts == ["tenant-a.mx.us.example.test."]
    assert resolved.spf.required_includes == ["spf.tenant-a.example.test"]
    assert resolved.spf.strict_record == "v=spf1 include:spf.tenant-a.example.test -all"
    assert resolved.spf.required_modifiers["redirect"] == "_spf.tenant-a.example.test"
    assert resolved.dkim.selectors == ["sel-tenant-a"]
    assert resolved.dkim.target_template == "{selector}._domainkey.tenant-a.example.test."
    assert resolved.cname.records == {
        "sip": "sip.tenant-a.example.test.",
        "discover": "webdir.tenant-a.",
    }
    assert resolved.cname.records_optional == {"autoconfig": "auto.tenant-a.example.test."}
    assert resolved.caa.records["@"][0].value == "ca.tenant-a.example.test"
    assert resolved.caa.records_optional["mail.example.test"][0].value == (
        "mailto:security@example.test"
    )
    assert resolved.srv.records["_sip._tls"][0].target == "sipdir.tenant-a.example.test."
    assert (
        resolved.srv.records_optional["_autodiscover._tcp"][0].target
        == "auto.tenant-a.example.test."
    )
    assert resolved.txt.required == {"_verify.example.test": ["token-tenant-a"]}
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
