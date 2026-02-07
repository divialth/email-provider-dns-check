import pytest

from provider_check.provider_config import (
    AddressConfig,
    DKIMConfig,
    DKIMRequired,
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    MXConfig,
    MXRecord,
    PTRConfig,
    ProviderConfig,
    ProviderVariable,
    SPFConfig,
    SPFOptional,
    SPFRequired,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    SRVConfig,
    SRVRecord,
    TLSAConfig,
    TLSARecord,
    TXTConfig,
    TXTSettings,
    resolve_provider_config,
)
from provider_check.provider_config.utils import _format_string


def test_resolve_provider_config_applies_variables_and_domain():
    provider = ProviderConfig(
        provider_id="var_provider",
        name="Variable Provider",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="{tenant}.mx.{region}.example.test.")],
            optional=[],
        ),
        spf=SPFConfig(
            required=SPFRequired(
                policy="hardfail",
                includes=["spf.{tenant}.example.test"],
                mechanisms=["exists:%{i}.spf.{tenant}.example.test"],
                modifiers={"redirect": "_spf.{tenant}.example.test"},
            ),
            optional=SPFOptional(mechanisms=[], modifiers={}),
        ),
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["sel-{tenant}"],
                record_type="cname",
                target_template="{selector}._domainkey.{tenant}.example.test.",
                txt_values={},
            )
        ),
        a=AddressConfig(
            required={"mail.{domain}": ["192.0.2.1"]},
            optional={"autodiscover.{domain}": ["192.0.2.2"]},
        ),
        aaaa=AddressConfig(
            required={"mail.{domain}": ["2001:db8::1"]},
            optional={"autodiscover.{domain}": ["2001:db8::2"]},
        ),
        ptr=PTRConfig(
            required={"10.2.0.192.in-addr.arpa.": ["mail.{tenant}.example.test."]},
            optional={"11.2.0.192.in-addr.arpa.": ["mx.{tenant}.example.test."]},
        ),
        cname=CNAMEConfig(
            required={"sip": "sip.{tenant}.example.test.", "discover": "webdir.{tenant}."},
            optional={"autoconfig": "auto.{tenant}.example.test."},
        ),
        caa=CAAConfig(
            required={"@": [CAARecord(flags=0, tag="issue", value="ca.{tenant}.example.test")]},
            optional={
                "mail.{domain}": [CAARecord(flags=0, tag="iodef", value="mailto:security@{domain}")]
            },
        ),
        srv=SRVConfig(
            required={
                "_sip._tls": [
                    SRVRecord(
                        priority=100,
                        weight=1,
                        port=443,
                        target="sipdir.{tenant}.example.test.",
                    )
                ]
            },
            optional={
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
        tlsa=TLSAConfig(
            required={
                "_25._tcp.mail": [
                    TLSARecord(
                        usage=3,
                        selector=1,
                        matching_type=1,
                        certificate_association="ABCDEF{tenant}",
                    )
                ]
            },
            optional={
                "_443._tcp.autodiscover": [
                    TLSARecord(
                        usage=3,
                        selector=1,
                        matching_type=1,
                        certificate_association="{region}1234",
                    )
                ]
            },
        ),
        txt=TXTConfig(
            required={"_verify.{domain}": ["token-{tenant}"]},
            optional={},
            settings=TXTSettings(verification_required=False),
        ),
        dmarc=DMARCConfig(
            required=DMARCRequired(
                policy="reject",
                rua=["mailto:dmarc@{domain}"],
                ruf=["mailto:forensic@{domain}"],
                tags={"pct": "100"},
            ),
            optional=DMARCOptional(rua=[], ruf=[]),
            settings=DMARCSettings(rua_required=False, ruf_required=False),
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

    assert [entry.host for entry in resolved.mx.required] == ["tenant-a.mx.us.example.test."]
    assert resolved.spf.required.policy == "hardfail"
    assert resolved.spf.required.includes == ["spf.tenant-a.example.test"]
    assert resolved.spf.required.modifiers["redirect"] == "_spf.tenant-a.example.test"
    assert resolved.dkim.required.selectors == ["sel-tenant-a"]
    assert resolved.dkim.required.target_template == "{selector}._domainkey.tenant-a.example.test."
    assert resolved.a.required == {"mail.example.test": ["192.0.2.1"]}
    assert resolved.a.optional == {"autodiscover.example.test": ["192.0.2.2"]}
    assert resolved.aaaa.required == {"mail.example.test": ["2001:db8::1"]}
    assert resolved.aaaa.optional == {"autodiscover.example.test": ["2001:db8::2"]}
    assert resolved.ptr.required == {"10.2.0.192.in-addr.arpa.": ["mail.tenant-a.example.test."]}
    assert resolved.ptr.optional == {"11.2.0.192.in-addr.arpa.": ["mx.tenant-a.example.test."]}
    assert resolved.cname.required == {
        "sip": "sip.tenant-a.example.test.",
        "discover": "webdir.tenant-a.",
    }
    assert resolved.cname.optional == {"autoconfig": "auto.tenant-a.example.test."}
    assert resolved.caa.required["@"][0].value == "ca.tenant-a.example.test"
    assert resolved.caa.optional["mail.example.test"][0].value == ("mailto:security@example.test")
    assert resolved.srv.required["_sip._tls"][0].target == "sipdir.tenant-a.example.test."
    assert resolved.srv.optional["_autodiscover._tcp"][0].target == "auto.tenant-a.example.test."
    assert resolved.tlsa.required["_25._tcp.mail"][0].certificate_association == "ABCDEFtenant-a"
    assert resolved.tlsa.optional["_443._tcp.autodiscover"][0].certificate_association == "us1234"
    assert resolved.txt.required == {"_verify.example.test": ["token-tenant-a"]}
    assert resolved.dmarc.required.rua == ["mailto:dmarc@example.test"]
    assert resolved.dmarc.required.ruf == ["mailto:forensic@example.test"]


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


def test_resolve_provider_config_formats_spf_values():
    provider = ProviderConfig(
        provider_id="none_values",
        name="None Values",
        version="1",
        mx=None,
        spf=SPFConfig(
            required=SPFRequired(
                policy="hardfail",
                includes=["include.{token}.example.test"],
                mechanisms=[],
                modifiers={},
            ),
            optional=SPFOptional(mechanisms=[], modifiers={}),
        ),
        dkim=None,
        txt=None,
        dmarc=None,
        variables={"token": ProviderVariable(name="token", required=False)},
    )

    resolved = resolve_provider_config(provider, {"token": "value"})

    assert resolved.spf.required.policy == "hardfail"
    assert resolved.spf.required.includes == ["include.value.example.test"]


def test_resolve_provider_config_rejects_invalid_dkim_placeholder():
    provider = ProviderConfig(
        provider_id="invalid_dkim_template",
        name="Invalid DKIM Template",
        version="1",
        mx=None,
        spf=None,
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector1"],
                record_type="cname",
                target_template="{selector}.{unknown}.example.test.",
                txt_values={},
            )
        ),
        txt=None,
        dmarc=None,
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )

    with pytest.raises(ValueError, match="unsupported placeholder"):
        resolve_provider_config(provider, {"tenant": "acme"}, domain="example.test")


def test_format_string_none_passthrough() -> None:
    """Return None when the template value is None."""
    assert _format_string(None, {"token": "value"}) is None
