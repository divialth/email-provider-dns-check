"""TLSA backend implementation tests."""

from __future__ import annotations

import subprocess

import pytest

from provider_check.checker import DNSChecker
from provider_check.checker.records import tlsa as tlsa_module

from tests.checker.tlsa_support import make_provider_with_tlsa, make_tlsa_config
from tests.support import FakeResolver


def _make_checker() -> DNSChecker:
    """Build a checker instance for backend helper tests.

    Returns:
        DNSChecker: Checker with an empty TLSA configuration.
    """
    provider = make_provider_with_tlsa(make_tlsa_config(required={}))
    return DNSChecker("example.com", provider, resolver=FakeResolver())


def test_extract_spki_der_with_cryptography_uses_backend_and_serialization(monkeypatch) -> None:
    """Extract DER SPKI bytes via the cryptography backend API shape."""
    checker = _make_checker()
    captured: dict[str, object] = {}

    class FakePublicKey:
        """Fake public key object with serialization output."""

        @staticmethod
        def public_bytes(*, encoding: object, format: object) -> bytes:
            captured["encoding"] = encoding
            captured["format"] = format
            return b"spki-der"

    class FakeCertificate:
        """Fake certificate exposing a public key."""

        @staticmethod
        def public_key() -> FakePublicKey:
            return FakePublicKey()

    class FakeX509:
        """Fake x509 module with DER loader."""

        @staticmethod
        def load_der_x509_certificate(certificate_der: bytes) -> FakeCertificate:
            captured["certificate_der"] = certificate_der
            return FakeCertificate()

    class FakeEncoding:
        """Fake encoding constants."""

        DER = object()

    class FakePublicFormat:
        """Fake public format constants."""

        SubjectPublicKeyInfo = object()

    monkeypatch.setattr(checker, "_has_cryptography", lambda: True)
    monkeypatch.setattr(tlsa_module, "cryptography_x509", FakeX509)
    monkeypatch.setattr(tlsa_module, "Encoding", FakeEncoding)
    monkeypatch.setattr(tlsa_module, "PublicFormat", FakePublicFormat)

    result = checker._extract_spki_der_with_cryptography(b"certificate-bytes")

    assert result == b"spki-der"
    assert captured["certificate_der"] == b"certificate-bytes"
    assert captured["encoding"] is FakeEncoding.DER
    assert captured["format"] is FakePublicFormat.SubjectPublicKeyInfo


def test_extract_spki_der_with_cryptography_reports_missing_dependency(monkeypatch) -> None:
    """Raise a clear error when cryptography backend is unavailable."""
    checker = _make_checker()
    monkeypatch.setattr(checker, "_has_cryptography", lambda: False)

    with pytest.raises(RuntimeError, match="cryptography is not installed"):
        checker._extract_spki_der_with_cryptography(b"certificate-bytes")


def test_extract_spki_der_with_cryptography_invalid_der_errors(monkeypatch) -> None:
    """Return an actionable error when certificate DER parsing fails."""
    checker = _make_checker()

    class FakeX509:
        """Fake x509 module with parse error."""

        @staticmethod
        def load_der_x509_certificate(_certificate_der: bytes) -> object:
            raise ValueError("bad certificate")

    class FakeEncoding:
        """Fake encoding constants."""

        DER = object()

    class FakePublicFormat:
        """Fake public format constants."""

        SubjectPublicKeyInfo = object()

    monkeypatch.setattr(checker, "_has_cryptography", lambda: True)
    monkeypatch.setattr(tlsa_module, "cryptography_x509", FakeX509)
    monkeypatch.setattr(tlsa_module, "Encoding", FakeEncoding)
    monkeypatch.setattr(tlsa_module, "PublicFormat", FakePublicFormat)

    with pytest.raises(RuntimeError, match="Failed to parse DER certificate"):
        checker._extract_spki_der_with_cryptography(b"not-a-valid-der-certificate")


def test_extract_spki_der_with_cryptography_wraps_unexpected_errors(monkeypatch) -> None:
    """Wrap unexpected cryptography backend errors as RuntimeError."""
    checker = _make_checker()

    class FakePublicKey:
        """Fake public key that fails serialization."""

        @staticmethod
        def public_bytes(*, encoding: object, format: object) -> bytes:
            del encoding, format
            raise TypeError("serialization failure")

    class FakeCertificate:
        """Fake certificate exposing a failing public key."""

        @staticmethod
        def public_key() -> FakePublicKey:
            return FakePublicKey()

    class FakeX509:
        """Fake x509 loader returning a certificate."""

        @staticmethod
        def load_der_x509_certificate(_certificate_der: bytes) -> FakeCertificate:
            return FakeCertificate()

    class FakeEncoding:
        """Fake encoding constants."""

        DER = object()

    class FakePublicFormat:
        """Fake public format constants."""

        SubjectPublicKeyInfo = object()

    monkeypatch.setattr(checker, "_has_cryptography", lambda: True)
    monkeypatch.setattr(tlsa_module, "cryptography_x509", FakeX509)
    monkeypatch.setattr(tlsa_module, "Encoding", FakeEncoding)
    monkeypatch.setattr(tlsa_module, "PublicFormat", FakePublicFormat)

    with pytest.raises(
        RuntimeError,
        match="Failed to extract DER SPKI with cryptography: serialization failure",
    ):
        checker._extract_spki_der_with_cryptography(b"certificate-bytes")


def test_extract_spki_der_with_openssl_runs_two_stage_pipeline(monkeypatch) -> None:
    """Run OpenSSL x509->pkey pipeline and return DER SPKI bytes."""
    checker = _make_checker()

    monkeypatch.setattr(tlsa_module.ssl, "DER_cert_to_PEM_cert", lambda _der: "PEM-CERT")

    calls: list[tuple[list[str], bytes]] = []

    def fake_run_openssl(
        args: list[str], *, timeout: int = 15, input_data: bytes = b""
    ) -> subprocess.CompletedProcess:
        calls.append((args, input_data))
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout=b"PUBKEY", stderr=b""
            )
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"SPKI-DER", stderr=b"")

    monkeypatch.setattr(checker, "_run_openssl", fake_run_openssl)

    result = checker._extract_spki_der_with_openssl(b"\x00")

    assert result == b"SPKI-DER"
    assert calls[0] == (["x509", "-pubkey", "-noout"], b"PEM-CERT")
    assert calls[1] == (["pkey", "-pubin", "-outform", "DER"], b"PUBKEY")


def test_extract_spki_der_with_openssl_reports_pubkey_extraction_error(monkeypatch) -> None:
    """Raise a RuntimeError when OpenSSL cannot extract public key bytes."""
    checker = _make_checker()

    monkeypatch.setattr(tlsa_module.ssl, "DER_cert_to_PEM_cert", lambda _der: "PEM-CERT")
    monkeypatch.setattr(
        checker,
        "_run_openssl",
        lambda _args, *, timeout=15, input_data=b"": subprocess.CompletedProcess(
            args=["x509", "-pubkey", "-noout"],
            returncode=1,
            stdout=b"",
            stderr=b"bad cert",
        ),
    )

    with pytest.raises(RuntimeError, match="Failed to extract certificate public key: bad cert"):
        checker._extract_spki_der_with_openssl(b"\x00")


def test_fetch_peer_cert_chain_dispatches_between_backends(monkeypatch) -> None:
    """Use pyOpenSSL when present and OpenSSL fallback otherwise."""
    checker = _make_checker()

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(
        checker, "_fetch_peer_cert_chain_with_pyopenssl", lambda _host, _port: [b"py"]
    )
    monkeypatch.setattr(
        checker, "_fetch_peer_cert_chain_with_openssl", lambda _host, _port: [b"openssl"]
    )
    assert checker._fetch_peer_cert_chain("mail.example.com", 25) == [b"py"]

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: False)
    assert checker._fetch_peer_cert_chain("mail.example.com", 25) == [b"openssl"]


def test_verify_tlsa_bindings_handles_unexpected_fetch_error(monkeypatch) -> None:
    """Convert unexpected certificate-fetch errors into endpoint errors."""
    checker = _make_checker()

    def _raise_fetch_error(_host: str, _port: int) -> list[bytes]:
        raise TypeError("fetch failed")

    monkeypatch.setattr(checker, "_fetch_peer_cert_chain", _raise_fetch_error)

    verification = checker._verify_tlsa_bindings({"_25._tcp.mail.example.com": [(3, 1, 1, "aabb")]})

    assert verification["endpoint_errors"] == {"_25._tcp.mail.example.com": "fetch failed"}


def test_verify_tlsa_bindings_handles_unexpected_pkix_error(monkeypatch) -> None:
    """Convert unexpected PKIX validation errors into endpoint errors."""
    checker = _make_checker()
    monkeypatch.setattr(checker, "_fetch_peer_cert_chain", lambda _host, _port: [b"leaf"])

    def _raise_pkix_error(_host: str, _port: int) -> tuple[bool, str]:
        raise TypeError("pkix failed")

    monkeypatch.setattr(checker, "_check_pkix_validation", _raise_pkix_error)

    verification = checker._verify_tlsa_bindings({"_25._tcp.mail.example.com": [(3, 1, 1, "aabb")]})

    assert verification["endpoint_errors"] == {"_25._tcp.mail.example.com": "pkix failed"}


def test_verify_tlsa_bindings_handles_unexpected_match_error(monkeypatch) -> None:
    """Convert unexpected TLSA/certificate comparison errors into endpoint errors."""
    checker = _make_checker()
    monkeypatch.setattr(checker, "_fetch_peer_cert_chain", lambda _host, _port: [b"leaf"])
    monkeypatch.setattr(checker, "_check_pkix_validation", lambda _host, _port: (True, "0 (ok)"))

    def _raise_match_error(
        _entry: tuple[int, int, int, str],
        _certificate_der: bytes,
        _spki_cache: dict[bytes, bytes],
    ) -> bool:
        raise TypeError("match failed")

    monkeypatch.setattr(checker, "_tlsa_entry_matches_certificate", _raise_match_error)

    verification = checker._verify_tlsa_bindings({"_25._tcp.mail.example.com": [(3, 1, 1, "aabb")]})

    assert verification["endpoint_errors"] == {"_25._tcp.mail.example.com": "match failed"}
