from provider_check.provider_config import (
    DKIMConfig,
    DMARCConfig,
    MXConfig,
    ProviderConfig,
    SPFConfig,
)

BASE_PROVIDER = ProviderConfig(
    provider_id="dummy_provider",
    name="Dummy Provider",
    version="1",
    mx=MXConfig(hosts=["mx1.dummy.test.", "mx2.dummy.test."], priorities={}),
    spf=SPFConfig(
        required_includes=["dummy.test"],
        strict_record="v=spf1 include:dummy.test -all",
        required_mechanisms=[],
        allowed_mechanisms=[],
        required_modifiers={},
    ),
    dkim=DKIMConfig(
        selectors=["DUMMY1", "DUMMY2", "DUMMY3", "DUMMY4"],
        record_type="cname",
        target_template="{selector}._domainkey.dummy.test.",
        txt_values={},
    ),
    txt=None,
    dmarc=DMARCConfig(
        default_policy="reject",
        default_rua_localpart="postmaster",
        required_rua=[],
        required_tags={},
    ),
)


class FakeResolver:
    def __init__(self, mx=None, txt=None, cname=None):
        self.mx = mx or {}
        self.txt = txt or {}
        self.cname = cname or {}

    def get_mx(self, domain: str):
        return self.mx.get(domain, [])

    def get_txt(self, domain: str):
        return self.txt.get(domain, [])

    def get_cname(self, name: str):
        return self.cname.get(name)
