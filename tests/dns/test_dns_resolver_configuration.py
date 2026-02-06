from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from provider_check.dns_resolver import DnsResolver

from tests.dns.support import make_dummy_resolver


def test_nameserver_ips_are_used(monkeypatch):
    dummy = make_dummy_resolver(monkeypatch)

    DnsResolver(nameservers=["1.1.1.1", "2001:db8::1"])

    assert dummy.nameservers == ["1.1.1.1", "2001:db8::1"]


def test_nameserver_duplicates_are_deduped(monkeypatch):
    dummy = make_dummy_resolver(monkeypatch)

    DnsResolver(nameservers=["1.1.1.1", "1.1.1.1"])

    assert dummy.nameservers == ["1.1.1.1"]


def test_nameserver_hostnames_are_resolved(monkeypatch):
    dummy = make_dummy_resolver(
        monkeypatch,
        {
            ("dns.example.test", "A"): [SimpleNamespace(address="203.0.113.53")],
            ("dns.example.test", "AAAA"): [SimpleNamespace(address="2001:db8::53")],
        },
    )

    DnsResolver(nameservers=["dns.example.test"])

    assert dummy.nameservers == ["203.0.113.53", "2001:db8::53"]


def test_nameserver_hostname_without_addresses_raises(monkeypatch):
    make_dummy_resolver(
        monkeypatch,
        {
            ("dns.example.test", "A"): dns.resolver.NXDOMAIN(),
            ("dns.example.test", "AAAA"): dns.resolver.NoAnswer(),
        },
    )

    with pytest.raises(ValueError, match="did not resolve to any IP addresses"):
        DnsResolver(nameservers=["dns.example.test"])


def test_nameserver_hostname_dns_exception_raises(monkeypatch):
    make_dummy_resolver(
        monkeypatch,
        {
            ("dns.example.test", "A"): dns.exception.DNSException("boom"),
            ("dns.example.test", "AAAA"): dns.resolver.NoAnswer(),
        },
    )

    with pytest.raises(ValueError, match="could not be resolved"):
        DnsResolver(nameservers=["dns.example.test"])


def test_empty_nameserver_entry_raises(monkeypatch):
    make_dummy_resolver(monkeypatch)

    with pytest.raises(ValueError, match="cannot be empty"):
        DnsResolver(nameservers=[""])


def test_empty_nameserver_list_raises(monkeypatch):
    make_dummy_resolver(monkeypatch)
    resolver = DnsResolver()

    with pytest.raises(ValueError, match="At least one DNS server must be provided"):
        resolver._resolve_nameservers([])


def test_dns_timeout_lifetime_and_tcp_are_set(monkeypatch):
    dummy = make_dummy_resolver(monkeypatch)

    DnsResolver(timeout=2.5, lifetime=7.0, use_tcp=True)

    assert dummy.timeout == 2.5
    assert dummy.lifetime == 7.0
    assert dummy.use_tcp is True


def test_dns_timeout_rejects_non_positive(monkeypatch):
    make_dummy_resolver(monkeypatch)

    with pytest.raises(ValueError, match="DNS timeout must be a positive number"):
        DnsResolver(timeout=0)


def test_dns_lifetime_rejects_non_positive(monkeypatch):
    make_dummy_resolver(monkeypatch)

    with pytest.raises(ValueError, match="DNS lifetime must be a positive number"):
        DnsResolver(lifetime=-1)
