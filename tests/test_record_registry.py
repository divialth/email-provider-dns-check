from provider_check.provider_config import (
    AddressConfig,
    CAAConfig,
    CAARecord,
    CNAMEConfig,
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    SPFConfig,
    SRVConfig,
    SRVRecord,
    TXTConfig,
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
        mx=MXConfig(hosts=["mx.test."], priorities={}),
        spf=SPFConfig(
            required_includes=["spf.test"],
            strict_record=None,
            required_mechanisms=[],
            allowed_mechanisms=[],
            required_modifiers={},
        ),
        dkim=DKIMConfig(
            selectors=["selector"],
            record_type="cname",
            target_template="{selector}._domainkey.example.test.",
            txt_values={},
        ),
        a=AddressConfig(
            records={"mail": ["192.0.2.1"]},
            records_optional={"optional": ["192.0.2.2"]},
        ),
        aaaa=AddressConfig(
            records={"mail": ["2001:db8::1"]},
            records_optional={"optional": ["2001:db8::2"]},
        ),
        cname=CNAMEConfig(
            records={"autodiscover": "target.example.test."},
            records_optional={"optional": "optional.example.test."},
        ),
        caa=CAAConfig(
            records={"@": [CAARecord(flags=0, tag="issue", value="example.test")]},
            records_optional={"@": [CAARecord(flags=0, tag="issue", value="optional.test")]},
        ),
        srv=SRVConfig(
            records={"_sip._tcp": [SRVRecord(priority=1, weight=1, port=5060, target="sip.test.")]},
            records_optional={
                "_sip._udp": [SRVRecord(priority=1, weight=1, port=5060, target="sip.test.")]
            },
        ),
        txt=TXTConfig(
            records={"@": ["value"]},
            records_optional={"@": ["optional"]},
            verification_required=False,
        ),
        dmarc=DMARCConfig(
            default_policy="reject",
            required_rua=[],
            required_ruf=[],
            required_tags={},
        ),
    )


def test_check_specs_enablement() -> None:
    checker = DummyChecker(_build_provider())
    for spec in CHECK_SPECS:
        assert spec.enabled_when(checker) is True


def test_record_type_registry_consistency() -> None:
    record_types = {spec.record_type for spec in RECORD_TYPE_SPECS}
    assert record_types == set(TYPE_WEIGHTS)
    assert record_types == set(ROW_BUILDER_NAMES)
    assert CORE_RECORD_TYPES.issubset(record_types)
