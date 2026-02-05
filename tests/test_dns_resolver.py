from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from provider_check.dns_resolver import CachingResolver, DnsLookupError, DnsResolver


class DummyResolver:
    def __init__(self, answers):
        self.answers = answers
        self.nameservers = []
        self.timeout = None
        self.lifetime = None
        self.use_tcp = False

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


def test_get_srv_success(monkeypatch):
    answers = {
        ("_sip._tls.example.com", "SRV"): [
            SimpleNamespace(priority=100, weight=1, port=443, target="sip.provider.test."),
            SimpleNamespace(priority=100, weight=1, port=5061, target="sip.extra.provider.test."),
        ]
    }
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_srv("_sip._tls.example.com") == [
        (100, 1, 443, "sip.provider.test."),
        (100, 1, 5061, "sip.extra.provider.test."),
    ]


def test_get_srv_no_answer_returns_empty(monkeypatch):
    answers = {("_sip._tls.example.com", "SRV"): dns.resolver.NoAnswer()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_srv("_sip._tls.example.com") == []


def test_get_srv_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("_sip._tls.example.com", "SRV"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

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
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_caa("example.com") == [
        (0, "issue", "ca.example.test"),
        (0, "issuewild", "ca.example.test"),
    ]


def test_get_caa_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "CAA"): dns.resolver.NoAnswer()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_caa("example.com") == []


def test_get_caa_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "CAA"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_caa("example.com")

    assert exc.value.record_type == "CAA"
    assert exc.value.name == "example.com"


def test_get_a_success(monkeypatch):
    answers = {
        ("example.com", "A"): [
            SimpleNamespace(address="192.0.2.1"),
            SimpleNamespace(address="192.0.2.2"),
        ]
    }
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_a("example.com") == ["192.0.2.1", "192.0.2.2"]


def test_get_a_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "A"): dns.resolver.NoAnswer()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_a("example.com") == []


def test_get_a_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "A"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

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
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_aaaa("example.com") == ["2001:db8::1", "2001:db8::2"]


def test_get_aaaa_no_answer_returns_empty(monkeypatch):
    answers = {("example.com", "AAAA"): dns.resolver.NoAnswer()}
    resolver = _make_resolver(monkeypatch, answers)

    assert resolver.get_aaaa("example.com") == []


def test_get_aaaa_dns_exception_raises_lookup_error(monkeypatch):
    answers = {("example.com", "AAAA"): dns.exception.DNSException("boom")}
    resolver = _make_resolver(monkeypatch, answers)

    with pytest.raises(DnsLookupError) as exc:
        resolver.get_aaaa("example.com")

    assert exc.value.record_type == "AAAA"
    assert exc.value.name == "example.com"


def test_caching_resolver_caches_successful_lookup():
    class _Resolver:
        def __init__(self):
            self.calls = 0

        def get_mx(self, domain: str):
            self.calls += 1
            return [("mx.example.test.", 10)]

    resolver = _Resolver()
    cached = CachingResolver(resolver)

    assert cached.get_mx("example.com") == [("mx.example.test.", 10)]
    assert cached.get_mx("example.com") == [("mx.example.test.", 10)]
    assert resolver.calls == 1


def test_caching_resolver_caches_errors():
    class _Resolver:
        def __init__(self):
            self.calls = 0

        def get_txt(self, domain: str):
            self.calls += 1
            raise DnsLookupError("TXT", domain, ValueError("boom"))

    resolver = _Resolver()
    cached = CachingResolver(resolver)

    with pytest.raises(DnsLookupError):
        cached.get_txt("example.com")
    with pytest.raises(DnsLookupError):
        cached.get_txt("example.com")

    assert resolver.calls == 1


def test_caching_resolver_supports_caa():
    class _Resolver:
        def get_caa(self, name: str):
            return [(0, "issue", "example.test")]

    cached = CachingResolver(_Resolver())

    assert cached.get_caa("example.com") == [(0, "issue", "example.test")]


def test_nameserver_ips_are_used(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    DnsResolver(nameservers=["1.1.1.1", "2001:db8::1"])

    assert dummy.nameservers == ["1.1.1.1", "2001:db8::1"]


def test_nameserver_duplicates_are_deduped(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    DnsResolver(nameservers=["1.1.1.1", "1.1.1.1"])

    assert dummy.nameservers == ["1.1.1.1"]


def test_nameserver_hostnames_are_resolved(monkeypatch):
    answers = {
        ("dns.example.test", "A"): [SimpleNamespace(address="203.0.113.53")],
        ("dns.example.test", "AAAA"): [SimpleNamespace(address="2001:db8::53")],
    }
    dummy = DummyResolver(answers)
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    DnsResolver(nameservers=["dns.example.test"])

    assert dummy.nameservers == ["203.0.113.53", "2001:db8::53"]


def test_nameserver_hostname_without_addresses_raises(monkeypatch):
    answers = {
        ("dns.example.test", "A"): dns.resolver.NXDOMAIN(),
        ("dns.example.test", "AAAA"): dns.resolver.NoAnswer(),
    }
    dummy = DummyResolver(answers)
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    with pytest.raises(ValueError):
        DnsResolver(nameservers=["dns.example.test"])


def test_nameserver_hostname_dns_exception_raises(monkeypatch):
    answers = {
        ("dns.example.test", "A"): dns.exception.DNSException("boom"),
        ("dns.example.test", "AAAA"): dns.resolver.NoAnswer(),
    }
    dummy = DummyResolver(answers)
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    with pytest.raises(ValueError):
        DnsResolver(nameservers=["dns.example.test"])


def test_empty_nameserver_entry_raises(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    with pytest.raises(ValueError):
        DnsResolver(nameservers=[""])


def test_empty_nameserver_list_raises(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)
    resolver = DnsResolver()

    with pytest.raises(ValueError):
        resolver._resolve_nameservers([])


def test_dns_timeout_lifetime_and_tcp_are_set(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    DnsResolver(timeout=2.5, lifetime=7.0, use_tcp=True)

    assert dummy.timeout == 2.5
    assert dummy.lifetime == 7.0
    assert dummy.use_tcp is True


def test_dns_timeout_rejects_non_positive(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    with pytest.raises(ValueError):
        DnsResolver(timeout=0)


def test_dns_lifetime_rejects_non_positive(monkeypatch):
    dummy = DummyResolver({})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)

    with pytest.raises(ValueError):
        DnsResolver(lifetime=-1)
