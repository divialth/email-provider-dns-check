from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from provider_check.dns_resolver import DnsLookupError, DnsResolver


class DummyResolver:
    def __init__(self, answers):
        self.answers = answers

    def resolve(self, name: str, record_type: str):
        result = self.answers[(name, record_type)]
        if isinstance(result, Exception):
            raise result
        return result


def _make_resolver(monkeypatch, answers):
    dummy = DummyResolver(answers)
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)
    return DnsResolver()


def test_get_mx_success(monkeypatch):
    answers = {
        ("example.com", "MX"): [
            SimpleNamespace(exchange="MX1.Example.", preference=10),
            SimpleNamespace(exchange="mx2.example.", preference=20),
        ]
    }
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_mx("example.com") == [
        ("mx1.example.", 10),
        ("mx2.example.", 20),
    ]


def test_get_mx_nxdomain_returns_empty(monkeypatch):
    answers = {("example.com", "MX"): dns.resolver.NXDOMAIN()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_mx("example.com") == []


def test_get_mx_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "MX"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

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
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_txt("example.com") == ["v=spf1 include:example -all"]


def test_get_txt_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "TXT"): dns.resolver.NoAnswer()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_txt("example.com") == []


def test_get_txt_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "TXT"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

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
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_cname("selector._domainkey.example.com") == "target.example."


def test_get_cname_nxdomain_returns_none(monkeypatch):
    answers = {("selector._domainkey.example.com", "CNAME"): dns.resolver.NXDOMAIN()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_cname("selector._domainkey.example.com") is None


def test_get_cname_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("selector._domainkey.example.com", "CNAME"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_cname("selector._domainkey.example.com")

    assert exc.value.record_type == "CNAME"
    assert exc.value.name == "selector._domainkey.example.com"
