from provider_check import detection
from provider_check.dns_resolver import DnsLookupError
from provider_check.provider_config import (
    CNAMEConfig,
    DKIMConfig,
    DKIMRequired,
    MXConfig,
    MXRecord,
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
    assert (
        detection._normalize_record_name("mail.example.net", domain)
        == "mail.example.net.example.com"
    )


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
        mx=MXConfig(required=[MXRecord(host="{tenant}.mx.test.")], optional=[]),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_from_mx_success():
    provider = _provider(
        mx=MXConfig(required=[MXRecord(host="{tenant}.mx.test.")], optional=[]),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(mx={"example.com": [("acme.mx.test.", 10)]})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred["tenant"] == "acme"


def test_infer_provider_variables_from_dkim_cname():
    provider = _provider(
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector1"],
                record_type="cname",
                target_template="{selector}.{tenant}.dkim.test.",
                txt_values={},
            )
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": "selector1.acme.dkim.test."})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred["tenant"] == "acme"


def test_infer_provider_variables_handles_missing_dkim_template():
    provider = _provider(
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector1"],
                record_type="cname",
                target_template=None,
                txt_values={},
            )
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": "selector1.acme.dkim.test."})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_from_cname_and_srv():
    provider = _provider(
        cname=CNAMEConfig(required={"mail": "{tenant}.cname.test."}),
        srv=SRVConfig(required={"_sip._tls": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
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
        cname=CNAMEConfig(required={"{tenant}": "{tenant}.cname.test."}),
        srv=SRVConfig(required={"{tenant}": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver()
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_dkim_lookup_error():
    provider = _provider(
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector1"],
                record_type="cname",
                target_template="{selector}.{tenant}.dkim.test.",
                txt_values={},
            )
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_skips_missing_dkim_target():
    provider = _provider(
        dkim=DKIMConfig(
            required=DKIMRequired(
                selectors=["selector1"],
                record_type="cname",
                target_template="{selector}.{tenant}.dkim.test.",
                txt_values={},
            )
        ),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"selector1._domainkey.example.com": None})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_cname_lookup_error():
    provider = _provider(
        cname=CNAMEConfig(required={"mail": "{tenant}.cname.test."}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_skips_missing_cname_target():
    provider = _provider(
        cname=CNAMEConfig(required={"mail": "{tenant}.cname.test."}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(cname={"mail.example.com": None})
    inferred = detection.infer_provider_variables(provider, "example.com", resolver)
    assert inferred == {}


def test_infer_provider_variables_handles_srv_lookup_error():
    provider = _provider(
        srv=SRVConfig(required={"_sip._tls": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    inferred = detection.infer_provider_variables(provider, "example.com", _FailingResolver())
    assert inferred == {}


def test_infer_provider_variables_from_srv_relative_dotted_name():
    provider = _provider(
        srv=SRVConfig(required={"_sip._tls": [SRVRecord(1, 1, 443, "{tenant}.srv.test.")]}),
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    resolver = _Resolver(srv={"_sip._tls.example.com": [(1, 1, 443, "acme.srv.test.")]})

    inferred = detection.infer_provider_variables(provider, "example.com", resolver)

    assert inferred["tenant"] == "acme"


def test_detect_providers_skips_empty_results(monkeypatch):
    provider = _provider(provider_id="empty", name="Empty Provider")
    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    report = detection.detect_providers("example.com", resolver=_Resolver())
    assert report.candidates == []


def test_detect_providers_ignores_optional_results(monkeypatch):
    provider = _provider(
        provider_id="optional",
        name="Optional Provider",
        mx=MXConfig(required=[MXRecord(host="mx.optional.test.")], optional=[]),
    )

    class _Checker:
        def run_checks(self):
            return [
                RecordCheck.pass_("MX", "ok", {"found": ["mx.optional.test."]}),
                RecordCheck.warn(
                    "CNAME",
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


def test_detect_providers_does_not_count_non_required_core_passes(monkeypatch):
    provider = _provider(
        provider_id="negative-only",
        name="Negative Only Provider",
        mx=MXConfig(required=[MXRecord(host="mx.negative.test.")], optional=[]),
    )

    class _Checker:
        def run_checks(self):
            return [RecordCheck.pass_("MX", "No forbidden MX", {}, scope="forbidden")]

    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    monkeypatch.setattr(detection, "DNSChecker", lambda *_args, **_kwargs: _Checker())

    report = detection.detect_providers("example.com", resolver=_Resolver())

    assert report.candidates == []


def test_detect_providers_includes_negative_scope_status_keys(monkeypatch):
    provider = _provider(
        provider_id="negative-status",
        name="Negative Status Provider",
        mx=MXConfig(required=[MXRecord(host="mx.negative.test.")], optional=[]),
    )

    class _Checker:
        def run_checks(self):
            return [
                RecordCheck.pass_("MX", "ok", {"found": ["mx.negative.test."]}),
                RecordCheck.fail("MX", "Forbidden MX present", {}, scope="forbidden"),
                RecordCheck.warn("TXT", "Deprecated TXT present", {}, scope="deprecated"),
                RecordCheck.pass_("CNAME", "Optional CNAME present", {}, optional=True),
            ]

    monkeypatch.setattr(detection, "list_providers", lambda: [provider])
    monkeypatch.setattr(detection, "DNSChecker", lambda *_args, **_kwargs: _Checker())

    report = detection.detect_providers("example.com", resolver=_Resolver())

    assert report.candidates
    candidate = report.candidates[0]
    assert candidate.record_statuses["MX"] == "PASS"
    assert candidate.record_statuses["MX_FORB"] == "FAIL"
    assert candidate.record_statuses["TXT_DEP"] == "WARN"
    assert candidate.record_statuses["CNAME_OPT"] == "PASS"


def test_result_status_key_handles_unknown_scope_suffix() -> None:
    class _Result:
        record_type = "TXT"
        scope = "customscope"

    assert detection._result_status_key(_Result()) == "TXT_CUSTOMSCOPE"
