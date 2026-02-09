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
            policy="hardfail",
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
    supports_live_tls_verification = False

    def __init__(
        self,
        mx=None,
        txt=None,
        cname=None,
        srv=None,
        caa=None,
        tlsa=None,
        tlsa_dnssec=None,
        a=None,
        aaaa=None,
        ptr=None,
    ):
        self.mx = mx or {}
        self.txt = txt or {}
        self.cname = cname or {}
        self.srv = srv or {}
        self.caa = caa or {}
        self.tlsa = tlsa or {}
        self.tlsa_dnssec = tlsa_dnssec or {}
        self.a = a or {}
        self.aaaa = aaaa or {}
        self.ptr = ptr or {}

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

    def get_tlsa(self, name: str):
        return self.tlsa.get(name, [])

    def get_tlsa_with_status(self, name: str):
        records = self.get_tlsa(name)
        if not records:
            return [], None
        return records, self.tlsa_dnssec.get(name, True)

    def get_a(self, name: str):
        return self.a.get(name, [])

    def get_aaaa(self, name: str):
        return self.aaaa.get(name, [])

    def get_ptr(self, name: str):
        return self.ptr.get(name, [])
