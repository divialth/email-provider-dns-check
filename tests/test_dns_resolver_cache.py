import pytest

from provider_check.dns_resolver import CachingResolver, DnsLookupError


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
