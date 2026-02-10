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


def test_fetch_peer_cert_chain_with_pyopenssl_prefers_tlsv1_2_context(monkeypatch) -> None:
    """Prefer TLSv1.2 method when pyOpenSSL exposes it."""
    checker = _make_checker()
    captured: dict[str, object] = {}

    class FakeContext:
        """Fake pyOpenSSL context."""

        def __init__(self, method: object) -> None:
            captured["method"] = method

        @staticmethod
        def set_verify(_mode: object, _callback) -> None:
            return None

        @staticmethod
        def set_default_verify_paths() -> None:
            return None

    class FakeConnection:
        """Fake pyOpenSSL connection."""

        def __init__(self, _context: FakeContext, _tcp_socket: object) -> None:
            return None

        @staticmethod
        def set_tlsext_host_name(_hostname: bytes) -> None:
            return None

        @staticmethod
        def set_connect_state() -> None:
            return None

        @staticmethod
        def do_handshake() -> None:
            return None

        @staticmethod
        def get_peer_cert_chain() -> list[object]:
            return ["cert"]

        @staticmethod
        def shutdown() -> None:
            return None

        @staticmethod
        def close() -> None:
            return None

    class FakeOpenSSLSSL:
        """Fake OpenSSL.SSL module constants and factories."""

        TLSv1_2_METHOD = object()
        TLS_CLIENT_METHOD = object()
        VERIFY_NONE = object()
        OP_NO_SSLv2 = 0x01
        OP_NO_SSLv3 = 0x02
        OP_NO_TLSv1 = 0x04
        OP_NO_TLSv1_1 = 0x08
        TLS1_2_VERSION = object()
        Context = FakeContext
        Connection = FakeConnection

    class FakeOpenSSLCrypto:
        """Fake OpenSSL.crypto module constants and dump helper."""

        FILETYPE_ASN1 = object()

        @staticmethod
        def dump_certificate(_filetype: object, _certificate: object) -> bytes:
            return b"cert-der"

    class FakeSocket:
        """Fake TCP socket."""

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(tlsa_module, "OpenSSL_SSL", FakeOpenSSLSSL)
    monkeypatch.setattr(tlsa_module, "OpenSSL_crypto", FakeOpenSSLCrypto)
    monkeypatch.setattr(
        tlsa_module.socket, "create_connection", lambda _endpoint, timeout=10: FakeSocket()
    )

    result = checker._fetch_peer_cert_chain_with_pyopenssl("mail.example.com", 25)

    assert result == [b"cert-der"]
    assert captured["method"] is FakeOpenSSLSSL.TLSv1_2_METHOD


def test_fetch_peer_cert_chain_with_pyopenssl_falls_back_to_protocol_options(monkeypatch) -> None:
    """Exercise TLS_CLIENT fallback hardening path when TLSv1.2 check is bypassed."""
    checker = _make_checker()
    captured: dict[str, object] = {}

    class FakeContext:
        """Fake pyOpenSSL context with hardening hooks."""

        def __init__(self, method: object) -> None:
            captured["method"] = method
            captured["calls"] = []

        @staticmethod
        def set_verify(_mode: object, _callback) -> None:
            return None

        @staticmethod
        def set_default_verify_paths() -> None:
            return None

        def set_options(self, options: object) -> None:
            captured["calls"].append("set_options")
            captured["options"] = options

        def set_min_proto_version(self, version: object) -> None:
            captured["calls"].append("set_min_proto_version")
            captured["minimum_proto"] = version

    class FakeConnection:
        """Fake pyOpenSSL connection."""

        def __init__(self, _context: FakeContext, _tcp_socket: object) -> None:
            return None

        @staticmethod
        def set_tlsext_host_name(_hostname: bytes) -> None:
            return None

        @staticmethod
        def set_connect_state() -> None:
            return None

        @staticmethod
        def do_handshake() -> None:
            return None

        @staticmethod
        def get_peer_cert_chain() -> list[object]:
            return ["cert"]

        @staticmethod
        def shutdown() -> None:
            return None

        @staticmethod
        def close() -> None:
            return None

    class FakeOpenSSLSSL:
        """Fake OpenSSL.SSL module with protocol-option fallback constants."""

        TLSv1_2_METHOD = object()
        TLS_CLIENT_METHOD = object()
        TLS1_2_VERSION = object()
        VERIFY_NONE = object()
        OP_NO_SSLv2 = 0x01
        OP_NO_SSLv3 = 0x02
        OP_NO_TLSv1 = 0x04
        OP_NO_TLSv1_1 = 0x08
        Context = FakeContext
        Connection = FakeConnection

    class FakeOpenSSLCrypto:
        """Fake OpenSSL.crypto module constants and dump helper."""

        FILETYPE_ASN1 = object()

        @staticmethod
        def dump_certificate(_filetype: object, _certificate: object) -> bytes:
            return b"cert-der"

    class FakeSocket:
        """Fake TCP socket."""

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(tlsa_module, "OpenSSL_SSL", FakeOpenSSLSSL)
    monkeypatch.setattr(tlsa_module, "OpenSSL_crypto", FakeOpenSSLCrypto)
    monkeypatch.setattr(
        tlsa_module.socket, "create_connection", lambda _endpoint, timeout=10: FakeSocket()
    )
    original_hasattr = hasattr
    forced: dict[str, bool] = {"used": False}

    def fake_hasattr(obj: object, name: str) -> bool:
        if obj is FakeOpenSSLSSL and name == "TLSv1_2_METHOD" and not forced["used"]:
            forced["used"] = True
            return False
        return original_hasattr(obj, name)

    monkeypatch.setattr("builtins.hasattr", fake_hasattr)

    result = checker._fetch_peer_cert_chain_with_pyopenssl("mail.example.com", 25)

    assert result == [b"cert-der"]
    assert captured["method"] is FakeOpenSSLSSL.TLSv1_2_METHOD
    assert captured["options"] == 0x0F
    assert captured["minimum_proto"] is FakeOpenSSLSSL.TLS1_2_VERSION
    assert captured["calls"] == ["set_min_proto_version", "set_options"]


def test_fetch_peer_cert_chain_with_pyopenssl_uses_tlsv1_2_method_fallback(monkeypatch) -> None:
    """Prefer TLSv1.2 method when it is available."""
    checker = _make_checker()
    captured: dict[str, object] = {}

    class FakeContext:
        """Fake pyOpenSSL context."""

        def __init__(self, method: object) -> None:
            captured["method"] = method

        @staticmethod
        def set_verify(_mode: object, _callback) -> None:
            return None

        @staticmethod
        def set_default_verify_paths() -> None:
            return None

    class FakeConnection:
        """Fake pyOpenSSL connection."""

        def __init__(self, _context: FakeContext, _tcp_socket: object) -> None:
            return None

        @staticmethod
        def set_tlsext_host_name(_hostname: bytes) -> None:
            return None

        @staticmethod
        def set_connect_state() -> None:
            return None

        @staticmethod
        def do_handshake() -> None:
            return None

        @staticmethod
        def get_peer_cert_chain() -> list[object]:
            return ["cert"]

        @staticmethod
        def shutdown() -> None:
            return None

        @staticmethod
        def close() -> None:
            return None

    class FakeOpenSSLSSL:
        """Fake OpenSSL.SSL module exposing both client methods."""

        TLS_CLIENT_METHOD = object()
        TLSv1_2_METHOD = object()
        VERIFY_NONE = object()
        Context = FakeContext
        Connection = FakeConnection

    class FakeOpenSSLCrypto:
        """Fake OpenSSL.crypto module constants and dump helper."""

        FILETYPE_ASN1 = object()

        @staticmethod
        def dump_certificate(_filetype: object, _certificate: object) -> bytes:
            return b"cert-der"

    class FakeSocket:
        """Fake TCP socket."""

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(tlsa_module, "OpenSSL_SSL", FakeOpenSSLSSL)
    monkeypatch.setattr(tlsa_module, "OpenSSL_crypto", FakeOpenSSLCrypto)
    monkeypatch.setattr(
        tlsa_module.socket, "create_connection", lambda _endpoint, timeout=10: FakeSocket()
    )

    result = checker._fetch_peer_cert_chain_with_pyopenssl("mail.example.com", 25)

    assert result == [b"cert-der"]
    assert captured["method"] is FakeOpenSSLSSL.TLSv1_2_METHOD
    assert "options" not in captured
    assert "minimum_proto" not in captured


def test_fetch_peer_cert_chain_with_pyopenssl_requires_secure_client_method(monkeypatch) -> None:
    """Raise a clear error when pyOpenSSL lacks secure TLS client methods."""
    checker = _make_checker()

    class FakeOpenSSLSSL:
        """Fake OpenSSL.SSL module without secure TLS client method constants."""

        VERIFY_NONE = object()

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(tlsa_module, "OpenSSL_SSL", FakeOpenSSLSSL)

    with pytest.raises(
        RuntimeError, match="pyOpenSSL does not expose secure TLS client method support"
    ):
        checker._fetch_peer_cert_chain_with_pyopenssl("mail.example.com", 25)


def test_fetch_peer_cert_chain_with_pyopenssl_requires_tlsv1_2_controls(monkeypatch) -> None:
    """Raise a clear error when TLSv1.2 minimum controls are unavailable."""
    checker = _make_checker()

    class FakeContext:
        """Fake pyOpenSSL context without minimum-version controls."""

    class FakeOpenSSLSSL:
        """Fake OpenSSL.SSL module without option flags and min-version API."""

        TLS_CLIENT_METHOD = object()
        VERIFY_NONE = object()
        Context = FakeContext

    monkeypatch.setattr(checker, "_has_pyopenssl", lambda: True)
    monkeypatch.setattr(tlsa_module, "OpenSSL_SSL", FakeOpenSSLSSL)

    with pytest.raises(
        RuntimeError, match="pyOpenSSL does not expose TLSv1.2 minimum protocol controls"
    ):
        checker._fetch_peer_cert_chain_with_pyopenssl("mail.example.com", 25)


def test_check_pkix_validation_sets_tlsv1_2_minimum(monkeypatch) -> None:
    """Set stdlib TLS context minimum protocol to TLSv1.2 before handshake."""
    checker = _make_checker()
    captured: dict[str, object] = {}

    class FakeWrappedSocket:
        """Fake wrapped socket context manager."""

        def __enter__(self) -> object:
            return object()

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            return None

    class FakeContext:
        """Fake stdlib SSL context with mutable protocol floor."""

        def __init__(self) -> None:
            self.minimum_version = None

        def wrap_socket(self, _tcp_socket: object, *, server_hostname: str) -> FakeWrappedSocket:
            captured["server_hostname"] = server_hostname
            captured["minimum_version"] = self.minimum_version
            return FakeWrappedSocket()

    class FakeSocket:
        """Fake TCP socket context manager."""

        def __enter__(self) -> object:
            return object()

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            return None

    fake_context = FakeContext()
    monkeypatch.setattr(tlsa_module.ssl, "create_default_context", lambda: fake_context)
    monkeypatch.setattr(
        tlsa_module.socket, "create_connection", lambda _endpoint, timeout=10: FakeSocket()
    )

    result = checker._check_pkix_validation("mail.example.com", 25)

    assert result == (True, "0 (ok)")
    assert captured["server_hostname"] == "mail.example.com"
    assert captured["minimum_version"] is tlsa_module.ssl.TLSVersion.TLSv1_2


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
