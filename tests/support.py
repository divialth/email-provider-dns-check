from provider_check.provider_config import (
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
)

BASE_PROVIDER = ProviderConfig(
    provider_id="dummy_provider",
    name="Dummy Provider",
    version="1",
    mx=MXConfig(
        required=[
            MXRecord(host="mx1.dummy.test."),
            MXRecord(host="mx2.dummy.test."),
        ],
        optional=[],
    ),
    spf=SPFConfig(
        required=SPFRequired(
            record="v=spf1 include:dummy.test -all",
            includes=["dummy.test"],
            mechanisms=[],
            modifiers={},
        ),
        optional=SPFOptional(mechanisms=[], modifiers={}),
    ),
    dkim=DKIMConfig(
        required=DKIMRequired(
            selectors=["DUMMY1", "DUMMY2", "DUMMY3", "DUMMY4"],
            record_type="cname",
            target_template="{selector}._domainkey.dummy.test.",
            txt_values={},
        )
    ),
    txt=None,
    dmarc=DMARCConfig(
        required=DMARCRequired(
            policy="reject",
            rua=["mailto:postmaster@{domain}"],
            ruf=[],
            tags={},
        ),
        optional=DMARCOptional(rua=[], ruf=[]),
        settings=DMARCSettings(rua_required=True, ruf_required=False),
    ),
)


class FakeResolver:
    def __init__(self, mx=None, txt=None, cname=None, srv=None, caa=None, a=None, aaaa=None):
        self.mx = mx or {}
        self.txt = txt or {}
        self.cname = cname or {}
        self.srv = srv or {}
        self.caa = caa or {}
        self.a = a or {}
        self.aaaa = aaaa or {}

    def get_mx(self, domain: str):
        return self.mx.get(domain, [])

    def get_txt(self, domain: str):
        return self.txt.get(domain, [])

    def get_cname(self, name: str):
        return self.cname.get(name)

    def get_srv(self, name: str):
        return self.srv.get(name, [])

    def get_caa(self, name: str):
        return self.caa.get(name, [])

    def get_a(self, name: str):
        return self.a.get(name, [])

    def get_aaaa(self, name: str):
        return self.aaaa.get(name, [])
