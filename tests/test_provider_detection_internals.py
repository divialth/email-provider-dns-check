from provider_check import detection
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import (
    CNAMEConfig,
    DKIMConfig,
    MXConfig,
    ProviderConfig,
    ProviderVariable,
    SRVConfig,
    SRVRecord,
)
from provider_check.checker import RecordCheck


class _FailingResolver:
    def get_mx(self, domain):
        raise DnsLookupError("MX", domain, RuntimeError("boom"))

    def get_cname(self, name):
        raise DnsLookupError("CNAME", name, RuntimeError("boom"))

    def get_srv(self, name):
        raise DnsLookupError("SRV", name, RuntimeError("boom"))


class _Resolver:
    def __init__(self, cname=None, srv=None, mx=None):
        self.cname = cname or {}
        self.srv = srv or {}
        self.mx = mx or {}

    def get_mx(self, domain):
        return self.mx.get(domain, [])

    def get_cname(self, name):
        return self.cname.get(name)

    def get_srv(self, name):
        return self.srv.get(name, [])


def _provider(**kwargs):
    return ProviderConfig(
        provider_id=kwargs.get("provider_id", "provider"),
        name=kwargs.get("name", "Provider"),
        version=kwargs.get("version", "1"),
        mx=kwargs.get("mx"),
        spf=None,
        dkim=kwargs.get("dkim"),
        cname=kwargs.get("cname"),
        srv=kwargs.get("srv"),
        txt=None,
        dmarc=None,
        variables=kwargs.get("variables", {}),
    )


def test_normalize_record_name_variants():
    domain = "example.com"
    assert detection._normalize_record_name("@", domain) == "example.com"
    assert detection._normalize_record_name("{domain}", domain) == "example.com"
    assert detection._normalize_record_name("mail.", domain) == "mail"
    assert detection._normalize_record_name("mx.example.com", domain) == "mx.example.com"
    assert detection._normalize_record_name("mx", domain) == "mx.example.com"
    assert detection._normalize_record_name("Mail.Example.com", domain) == "mail.example.com"
    assert detection._normalize_record_name("mail.example.net", domain) == "mail.example.net"


def test_template_regex_and_match_infer_branches():
    inferred = {}
    detection._match_and_infer("{tenant}.example.com.", [], {}, inferred, {"tenant"})
    assert inferred == {}

    inferred = {"tenant": "alpha"}
    detection._match_and_infer(
        "{tenant}.example.com.",
        ["beta.example.com."],
        {},
        inferred,
        {"tenant"},
    )
    assert inferred["tenant"] == "alpha"

    inferred = {}
    detection._match_and_infer(
        "{domain}.example.com.",
        ["example.example.com."],
        {"domain": "example"},
        inferred,
        set(),
    )
    assert inferred == {}

    inferred = {}
    detection._match_and_infer(
        "{unknown}.example.com.",
        ["value.example.com."],
        {},
        inferred,
        set(),
    )
    assert inferred == {}

    inferred = {}
    detection._match_and_infer(
        "{tenant}.example.com.",
        ["acme.example.com."],
        {},
        inferred,
        {"tenant"},
    )
    assert inferred["tenant"] == "acme"
    assert detection._normalize_host_template("mail.example.com") == "mail.example.com."


def test_infer_provider_variables_handles_mx_error():
    provider = _provider(
        mx=MXConfig(hosts=["{tenant}.mx.test."], priorities={}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_from_mx_success():
    provider = _provider(
        mx=MXConfig(hosts=["{tenant}.mx.test."], priorities={}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(mx={"example.com": [("acme.mx.test.", 10)]})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred["tenant"] == "acme"


def test_infer_provider_variables_from_dkim_cname():
    provider = _provider(
        dkim=DKIMConfig(
            selectors=["selector1"],
            record_type="cname",
            target_template="{selector}.{tenant}.dkim.test.",
            txt_values={},
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": "selector1.acme.dkim.test."})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred["tenant"] == "acme"


def test_infer_provider_variables_handles_missing_dkim_template():
    provider = _provider(
        dkim=DKIMConfig(
            selectors=["selector1"],
            record_type="cname",
            target_template=None,
            txt_values={},
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": "selector1.acme.dkim.test."})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_from_cname_and_srv():
    provider = _provider(
        cname=CNAMEConfig(records={"mail": "{tenant}.cname.test."}),
        srv=SRVConfig(records={"_sip._tls": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(
        cname={"mail.example.com": "acme.cname.test."},
        srv={"_sip._tls.example.com": [(1, 1, 443, "acme.srv.test.")]},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred["tenant"] == "acme"


def test_infer_provider_variables_skips_unresolved_names():
    provider = _provider(
        cname=CNAMEConfig(records={"{tenant}": "{tenant}.cname.test."}),
        srv=SRVConfig(records={"{tenant}": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver()
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_dkim_lookup_error():
    provider = _provider(
        dkim=DKIMConfig(
            selectors=["selector1"],
            record_type="cname",
            target_template="{selector}.{tenant}.dkim.test.",
            txt_values={},
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_skips_missing_dkim_target():
    provider = _provider(
        dkim=DKIMConfig(
            selectors=["selector1"],
            record_type="cname",
            target_template="{selector}.{tenant}.dkim.test.",
            txt_values={},
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": None})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_cname_lookup_error():
    provider = _provider(
        cname=CNAMEConfig(records={"mail": "{tenant}.cname.test."}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_skips_missing_cname_target():
    provider = _provider(
        cname=CNAMEConfig(records={"mail": "{tenant}.cname.test."}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"mail.example.com": None})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_srv_lookup_error():
    provider = _provider(
        srv=SRVConfig(records={"_sip._tls": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_detect_providers_skips_empty_results(monkeypatch):
    provider = _provider(provider_id="empty", name="Empty Provider")
    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    report = detection.detect_providers("example.com", resolver=_Resolver())
    assert report.candidates == []


def test_detect_providers_ignores_optional_results(monkeypatch):
    provider = _provider(
        provider_id="optional",
        name="Optional Provider",
        mx=MXConfig(hosts=["mx.optional.test."], priorities={}),
    )

    class _Checker:
        def run_checks(self):
            return [
                RecordCheck("MX", "PASS", "ok", {"found": ["mx.optional.test."]}),
                RecordCheck(
                    "CNAME",
                    "WARN",
                    "CNAME optional records missing",
                    {"missing": ["autoconfig.example.com"]},
                    optional=True,
                ),
            ]

    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    monkeypatch.setattr(detection, "DNSChecker", lambda *_args, **_kwargs: _Checker())

    report = detection.detect_providers("example.com", resolver=_Resolver())

    assert report.candidates
    candidate = report.candidates[0]
    assert candidate.status_counts["WARN"] == 1
    assert candidate.record_statuses == {"CNAME_OPT": "WARN", "MX": "PASS"}
