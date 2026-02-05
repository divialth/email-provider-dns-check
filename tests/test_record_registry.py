from provider_check.provider_config import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DKIMRequired,
    DMARCConfig,
    DMARCOptional,
    DMARCRequired,
    DMARCSettings,
    MXConfig,
    MXRecord,
    ProviderConfig,
    SPFConfig,
    SPFOptional,
    SPFRequired,
    SRVConfig,
    SRVRecord,
    TXTConfig,
    TXTSettings,
)
from provider_check.record_registry import (
    CHECK_SPECS,
    CORE_RECORD_TYPES,
    RECORD_TYPE_SPECS,
    ROW_BUILDER_NAMES,
    TYPE_WEIGHTS,
)


class DummyChecker:
    def __init__(self, provider):
        self.provider = provider
        self.additional_txt = {}
        self.additional_txt_verification = {}


def _build_provider() -> ProviderConfig:
    return ProviderConfig(
        provider_id="dummy",
        name="Dummy",
        version="1",
        mx=MXConfig(
            required=[MXRecord(host="mx.test.")],
            optional=[MXRecord(host="mx.optional.test.")],
        ),
        spf=SPFConfig(
            required=SPFRequired(
                record=None,
                includes=["spf.test"],
                mechanisms=[],
                modifiers={},
            ),
            optional=SPFOptional(mechanisms=[], modifiers={}),
        ),
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector"],
                record_type="cname",
                target_template="{selector}._domainkey.example.test.",
                txt_values={},
            )
        ),
        a=AddressConfig(
            required={"mail": ["192.0.2.1"]},
            optional={"optional": ["192.0.2.2"]},
        ),
        aaaa=AddressConfig(
            required={"mail": ["2001:db8::1"]},
            optional={"optional": ["2001:db8::2"]},
        ),
        cname=CNAMEConfig(
            required={"autodiscover": "target.example.test."},
            optional={"optional": "optional.example.test."},
        ),
        caa=CAAConfig(
            required={"@": [CAARecord(flags=0, tag="issue", value="example.test")]},
            optional={"@": [CAARecord(flags=0, tag="issue", value="optional.test")]},
        ),
        srv=SRVConfig(
            required={
                "_sip._tcp": [SRVRecord(priority=1, weight=1, port=5060, target="sip.test.")]
            },
            optional={
                "_sip._udp": [SRVRecord(priority=1, weight=1, port=5060, target="sip.test.")]
            },
        ),
        txt=TXTConfig(
            required={"@": ["value"]},
            optional={"@": ["optional"]},
            settings=TXTSettings(verification_required=False),
        ),
        dmarc=DMARCConfig(
            required=DMARCRequired(
                policy="reject",
                rua=[],
                ruf=[],
                tags={},
            ),
            optional=DMARCOptional(rua=[], ruf=[]),
            settings=DMARCSettings(rua_required=False, ruf_required=False),
        ),
    )


def test_check_specs_enablement() -> None:
    checker = DummyChecker(_build_provider())
    for spec in CHECK_SPECS:
        assert spec.enabled_when(checker) is True


def test_optional_only_mx_enables_optional_check() -> None:
    provider = ProviderConfig(
        provider_id="optional_mx",
        name="Optional MX",
        version="1",
        mx=MXConfig(required=[], optional=[MXRecord(host="mx.optional.test.")]),
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    checker = DummyChecker(provider)
    specs = {spec.check_method: spec for spec in CHECK_SPECS}

    assert specs["check_mx"].enabled_when(checker) is False
    assert specs["check_mx_optional"].enabled_when(checker) is True


def test_record_type_registry_consistency() -> None:
    record_types = {spec.record_type for spec in RECORD_TYPE_SPECS}
    assert record_types == set(TYPE_WEIGHTS)
    assert record_types == set(ROW_BUILDER_NAMES)
    assert CORE_RECORD_TYPES.issubset(record_types)
