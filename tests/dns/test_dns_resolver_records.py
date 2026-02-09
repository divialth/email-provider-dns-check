from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.resolver
import pytest

from provider_check.dns_resolver import DnsLookupError

from tests.dns.support import make_dns_resolver


def test_get_mx_success(monkeypatch):
    answers = {
        ("example.com", "MX"): [
            SimpleNamespace(exchange="MX1.Example.", preference=10),
            SimpleNamespace(exchange="mx2.example.", preference=20),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_mx("example.com") == [
        ("mx1.example.", 10),
        ("mx2.example.", 20),
    ]


def test_get_mx_nxdomain_returns_empty(monkeypatch):
    answers = {("example.com", "MX"): dns.resolver.NXDOMAIN()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_mx("example.com") == []


def test_get_mx_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "MX"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_mx("example.com")

    assert exc.value.record_type == "MX"
    assert exc.value.name == "example.com"


def test_get_txt_success(monkeypatch):
    answers = {
        ("example.com", "TXT"): [
            SimpleNamespace(strings=[b"v=spf1 ", b"include:example", " -all"]),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_txt("example.com") == ["v=spf1 include:example -all"]


def test_get_txt_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "TXT"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_txt("example.com") == []


def test_get_txt_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "TXT"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_txt("example.com")

    assert exc.value.record_type == "TXT"
    assert exc.value.name == "example.com"


def test_get_cname_success(monkeypatch):
    answers = {
        ("selector._domainkey.example.com", "CNAME"): [
            SimpleNamespace(target="Target.Example."),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_cname("selector._domainkey.example.com") == "target.example."


def test_get_cname_nxdomain_returns_none(monkeypatch):
    answers = {("selector._domainkey.example.com", "CNAME"): dns.resolver.NXDOMAIN()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_cname("selector._domainkey.example.com") is None


def test_get_cname_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("selector._domainkey.example.com", "CNAME"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_cname("selector._domainkey.example.com")

    assert exc.value.record_type == "CNAME"
    assert exc.value.name == "selector._domainkey.example.com"


def test_get_srv_success(monkeypatch):
    answers = {
        ("_sip._tls.example.com", "SRV"): [
            SimpleNamespace(priority=100, weight=1, port=443, target="sip.provider.test."),
            SimpleNamespace(priority=100, weight=1, port=5061, target="sip.extra.provider.test."),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_srv("_sip._tls.example.com") == [
        (100, 1, 443, "sip.provider.test."),
        (100, 1, 5061, "sip.extra.provider.test."),
    ]


def test_get_srv_no_answer_returns_empty(monkeypatch):
    answers = {("_sip._tls.example.com", "SRV"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_srv("_sip._tls.example.com") == []


def test_get_srv_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("_sip._tls.example.com", "SRV"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_srv("_sip._tls.example.com")

    assert exc.value.record_type == "SRV"
    assert exc.value.name == "_sip._tls.example.com"


def test_get_caa_success(monkeypatch):
    answers = {
        ("example.com", "CAA"): [
            SimpleNamespace(flags=0, tag="issue", value=b"ca.example.test"),
            SimpleNamespace(flags=0, tag="issuewild", value="ca.example.test"),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_caa("example.com") == [
        (0, "issue", "ca.example.test"),
        (0, "issuewild", "ca.example.test"),
    ]


def test_get_caa_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "CAA"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_caa("example.com") == []


def test_get_caa_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "CAA"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_caa("example.com")

    assert exc.value.record_type == "CAA"
    assert exc.value.name == "example.com"


def test_get_tlsa_success(monkeypatch):
    answers = {
        ("_25._tcp.mail.example.com", "TLSA"): [
            SimpleNamespace(usage=3, selector=1, mtype=1, cert=b"\xaa\xbb"),
            SimpleNamespace(
                usage=2,
                selector=0,
                matching_type=0,
                certificate_association=" CCDD ",
                cert="ignored",
            ),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_tlsa("_25._tcp.mail.example.com") == [
        (3, 1, 1, "aabb"),
        (2, 0, 0, "ccdd"),
    ]


def test_get_tlsa_with_status_reports_ad_bit(monkeypatch):
    class _Answer(list):
        def __init__(self, entries, flags):
            super().__init__(entries)
            self.response = SimpleNamespace(flags=flags)

    answers = {
        ("_25._tcp.mail.example.com", "TLSA"): _Answer(
            [SimpleNamespace(usage=3, selector=1, matching_type=1, certificate_association="aabb")],
            dns.flags.AD,
        ),
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    records, authenticated = resolver.get_tlsa_with_status("_25._tcp.mail.example.com")

    assert records == [(3, 1, 1, "aabb")]
    assert authenticated is True


def test_get_tlsa_with_status_returns_none_when_no_answer(monkeypatch):
    answers = {("_25._tcp.mail.example.com", "TLSA"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    records, authenticated = resolver.get_tlsa_with_status("_25._tcp.mail.example.com")

    assert records == []
    assert authenticated is None


def test_get_tlsa_no_answer_returns_empty(monkeypatch):
    answers = {("_25._tcp.mail.example.com", "TLSA"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_tlsa("_25._tcp.mail.example.com") == []


def test_get_tlsa_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("_25._tcp.mail.example.com", "TLSA"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_tlsa("_25._tcp.mail.example.com")

    assert exc.value.record_type == "TLSA"
    assert exc.value.name == "_25._tcp.mail.example.com"


def test_get_a_success(monkeypatch):
    answers = {
        ("example.com", "A"): [
            SimpleNamespace(address="192.0.2.1"),
            SimpleNamespace(address="192.0.2.2"),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_a("example.com") == ["192.0.2.1", "192.0.2.2"]


def test_get_a_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "A"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_a("example.com") == []


def test_get_a_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "A"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_a("example.com")

    assert exc.value.record_type == "A"
    assert exc.value.name == "example.com"


def test_get_aaaa_success(monkeypatch):
    answers = {
        ("example.com", "AAAA"): [
            SimpleNamespace(address="2001:db8::1"),
            SimpleNamespace(address="2001:db8::2"),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_aaaa("example.com") == ["2001:db8::1", "2001:db8::2"]


def test_get_aaaa_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "AAAA"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_aaaa("example.com") == []


def test_get_aaaa_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "AAAA"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_aaaa("example.com")

    assert exc.value.record_type == "AAAA"
    assert exc.value.name == "example.com"


def test_get_ptr_success(monkeypatch):
    answers = {
        ("10.2.0.192.in-addr.arpa", "PTR"): [
            SimpleNamespace(target="Mail.Example."),
            SimpleNamespace(target="mx1.example."),
        ]
    }
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_ptr("10.2.0.192.in-addr.arpa") == [
        "mail.example.",
        "mx1.example.",
    ]


def test_get_ptr_no_answer_returns_empty(monkeypatch):
    answers = {("10.2.0.192.in-addr.arpa", "PTR"): dns.resolver.NoAnswer()}
    resolver = make_dns_resolver(monkeypatch, answers)

    assert resolver.get_ptr("10.2.0.192.in-addr.arpa") == []


def test_get_ptr_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("10.2.0.192.in-addr.arpa", "PTR"): dns.exception.DNSException("boom")}
    resolver = make_dns_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_ptr("10.2.0.192.in-addr.arpa")

    assert exc.value.record_type == "PTR"
    assert exc.value.name == "10.2.0.192.in-addr.arpa"
