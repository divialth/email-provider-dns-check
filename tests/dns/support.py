"""Shared DNS resolver test support."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import dns.resolver
import pytest

from provider_check.dns_resolver import DnsResolver


class DummyResolver:
    """Minimal dnspython-compatible resolver test double.

    Attributes:
        answers (dict[tuple[str, str], Any]): Lookup results by (name, record_type).
        nameservers (list[str]): Assigned resolver nameservers.
        timeout (float | None): Per-query timeout.
        lifetime (float | None): Query lifetime.
        use_tcp (bool): Whether TCP lookups are enabled.
    """

    def __init__(self, answers: dict[tuple[str, str], Any]):
        """Initialize a dummy resolver.

        Args:
            answers (dict[tuple[str, str], Any]): Lookup responses keyed by query tuple.
        """
        self.answers = answers
        self.nameservers: list[str] = []
        self.timeout: float | None = None
        self.lifetime: float | None = None
        self.use_tcp = False

    def resolve(self, name: str, record_type: str) -> Any:
        """Resolve a record using predefined answers.

        Args:
            name (str): DNS name to resolve.
            record_type (str): DNS record type.

        Returns:
            Any: Preconfigured answer payload.

        Raises:
            Exception: Any configured exception value for the query key.
        """
        result = self.answers[(name, record_type)]
        if isinstance(result, Exception):
            raise result
        return result


def make_dummy_resolver(
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[tuple[str, str], Any] | None = None,
) -> DummyResolver:
    """Create and patch a dummy dnspython resolver.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        answers (dict[tuple[str, str], Any] | None): Optional preloaded lookup answers.

    Returns:
        DummyResolver: Patched dummy resolver instance.
    """
    dummy = DummyResolver(answers or {})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: dummy)
    return dummy


def make_dns_resolver(
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[tuple[str, str], Any],
) -> DnsResolver:
    """Create a ``DnsResolver`` backed by a patched dummy resolver.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        answers (dict[tuple[str, str], Any]): Lookup responses by query tuple.

    Returns:
        DnsResolver: Resolver under test.
    """
    make_dummy_resolver(monkeypatch, answers)
    return DnsResolver()


__all__ = ["DummyResolver", "SimpleNamespace", "make_dns_resolver", "make_dummy_resolver"]
