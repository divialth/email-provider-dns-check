"""TLSA record checks with DANE certificate verification."""

from __future__ import annotations

import hashlib
import re
import shutil
import socket
import ssl
import subprocess
from typing import Dict, List, Optional

from ...dns_resolver import DnsLookupError
from .models import RecordCheck

try:  # pragma: no cover - optional dependency
    from cryptography import x509 as cryptography_x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:  # pragma: no cover - optional dependency
    cryptography_x509 = None
    Encoding = None
    PublicFormat = None

try:  # pragma: no cover - optional dependency
    from OpenSSL import SSL as OpenSSL_SSL
    from OpenSSL import crypto as OpenSSL_crypto
except ImportError:  # pragma: no cover - optional dependency
    OpenSSL_SSL = None
    OpenSSL_crypto = None


class TlsaChecksMixin:
    """Validate TLSA records and verify certificate bindings."""

    _TLSA_PEM_RE = re.compile(
        b"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
        re.DOTALL,
    )

    def _evaluate_tlsa_records(
        self,
        records: Dict[str, List["TLSARecord"]],
    ) -> tuple[
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, Optional[bool]],
    ]:
        """Evaluate TLSA records and return missing/extra details.

        Args:
            records (Dict[str, List[TLSARecord]]): Expected TLSA records.

        Returns:
            tuple[Dict[str, List[tuple[int, int, int, str]]], ...]: Missing, extra,
                expected, found, and DNSSEC authentication status keyed by name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[tuple[int, int, int, str]]] = {}
        extra: Dict[str, List[tuple[int, int, int, str]]] = {}
        expected: Dict[str, List[tuple[int, int, int, str]]] = {}
        found: Dict[str, List[tuple[int, int, int, str]]] = {}
        dnssec_status: Dict[str, Optional[bool]] = {}

        for name, entries in records.items():
            lookup_name = self._normalize_record_name(name)
            expected_entries = [
                self._normalize_tlsa_entry(
                    entry.usage,
                    entry.selector,
                    entry.matching_type,
                    entry.certificate_association,
                )
                for entry in entries
            ]
            expected[lookup_name] = sorted(expected_entries)

            if hasattr(self.resolver, "get_tlsa_with_status"):
                found_entries_raw, authenticated = self.resolver.get_tlsa_with_status(lookup_name)
            else:
                found_entries_raw = self.resolver.get_tlsa(lookup_name)
                authenticated = None
            dnssec_status[lookup_name] = authenticated
            found_entries = [
                self._normalize_tlsa_entry(usage, selector, matching_type, certificate_association)
                for usage, selector, matching_type, certificate_association in found_entries_raw
            ]
            found[lookup_name] = sorted(found_entries)

            expected_set = set(expected_entries)
            found_set = set(found_entries)
            missing_entries = sorted(expected_set - found_set)
            extra_entries = sorted(found_set - expected_set)
            if missing_entries:
                missing[lookup_name] = missing_entries
            if extra_entries:
                extra[lookup_name] = extra_entries

        return missing, extra, expected, found, dnssec_status

    @staticmethod
    def _parse_tlsa_owner_name(name: str) -> Optional[tuple[int, str, str]]:
        """Parse a TLSA owner name into endpoint components.

        Args:
            name (str): Fully-qualified TLSA owner name.

        Returns:
            Optional[tuple[int, str, str]]: Parsed ``(port, transport, host)`` values,
                or ``None`` when the name does not follow ``_port._transport.host``.
        """
        labels = name.rstrip(".").lower().split(".")
        if len(labels) < 3:
            return None
        port_label, transport_label = labels[0], labels[1]
        if not port_label.startswith("_") or not transport_label.startswith("_"):
            return None
        port_text = port_label[1:]
        if not port_text.isdigit():
            return None
        host = ".".join(labels[2:]).strip()
        if not host:
            return None
        return int(port_text), transport_label[1:], host

    @staticmethod
    def _run_openssl(
        args: List[str], *, timeout: int = 15, input_data: bytes = b""
    ) -> subprocess.CompletedProcess:  # pragma: no cover - external OpenSSL integration
        """Run an OpenSSL command and capture output.

        Args:
            args (List[str]): OpenSSL arguments.
            timeout (int): Command timeout in seconds.
            input_data (bytes): Bytes to send to stdin.

        Returns:
            subprocess.CompletedProcess: Command result with stdout/stderr.

        Raises:
            RuntimeError: If the OpenSSL binary is unavailable.
        """
        openssl_binary = shutil.which("openssl")
        if not openssl_binary:
            raise RuntimeError("OpenSSL binary not found in PATH")
        return subprocess.run(
            [openssl_binary, *args],
            input=input_data,
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    @staticmethod
    def _has_pyopenssl() -> bool:
        """Return whether ``pyOpenSSL`` is available.

        Returns:
            bool: True when ``pyOpenSSL`` imports succeeded.
        """
        return OpenSSL_SSL is not None and OpenSSL_crypto is not None

    @staticmethod
    def _has_cryptography() -> bool:
        """Return whether ``pyca/cryptography`` is available.

        Returns:
            bool: True when ``cryptography`` imports succeeded.
        """
        return cryptography_x509 is not None and Encoding is not None and PublicFormat is not None

    @staticmethod
    def _create_secure_pyopenssl_context(
        openssl_ssl_module: "OpenSSL_SSL",
    ) -> "OpenSSL_SSL.Context":
        """Create a pyOpenSSL context using secure TLS client methods.

        Args:
            openssl_ssl_module (OpenSSL_SSL): pyOpenSSL SSL module object.

        Returns:
            OpenSSL_SSL.Context: TLS client context with a secure method.

        Raises:
            RuntimeError: If no secure TLS client method is available.
        """
        if hasattr(openssl_ssl_module, "TLS_CLIENT_METHOD"):
            return openssl_ssl_module.Context(openssl_ssl_module.TLS_CLIENT_METHOD)
        if hasattr(openssl_ssl_module, "TLSv1_2_METHOD"):
            return openssl_ssl_module.Context(openssl_ssl_module.TLSv1_2_METHOD)
        raise RuntimeError("pyOpenSSL does not expose secure TLS client method support")

    def _fetch_peer_cert_chain_with_pyopenssl(  # pragma: no cover - external pyOpenSSL integration
        self,
        host: str,
        port: int,
    ) -> List[bytes]:
        """Fetch peer certificate chain using ``pyOpenSSL``.

        Args:
            host (str): TLS server hostname.
            port (int): TLS server port.

        Returns:
            List[bytes]: Certificate chain in wire order (leaf first).

        Raises:
            RuntimeError: If certificates cannot be retrieved.
        """
        if not self._has_pyopenssl():
            raise RuntimeError("pyOpenSSL is not installed")

        context = self._create_secure_pyopenssl_context(OpenSSL_SSL)
        required_options = ("OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1")
        if not all(hasattr(OpenSSL_SSL, option_name) for option_name in required_options):
            raise RuntimeError("pyOpenSSL does not expose TLSv1.2 minimum protocol controls")
        context.set_options(
            OpenSSL_SSL.OP_NO_SSLv2
            | OpenSSL_SSL.OP_NO_SSLv3
            | OpenSSL_SSL.OP_NO_TLSv1
            | OpenSSL_SSL.OP_NO_TLSv1_1
        )
        if hasattr(context, "set_min_proto_version") and hasattr(OpenSSL_SSL, "TLS1_2_VERSION"):
            context.set_min_proto_version(OpenSSL_SSL.TLS1_2_VERSION)
        context.set_verify(OpenSSL_SSL.VERIFY_NONE, lambda *_args: True)
        context.set_default_verify_paths()

        tcp_socket = socket.create_connection((host, port), timeout=10)
        connection = OpenSSL_SSL.Connection(context, tcp_socket)
        try:
            connection.set_tlsext_host_name(host.encode("idna"))
            connection.set_connect_state()
            connection.do_handshake()
            chain = connection.get_peer_cert_chain() or []
            if not chain:
                peer = connection.get_peer_certificate()
                if peer is not None:
                    chain = [peer]
            if not chain:
                raise RuntimeError(f"No TLS certificates returned by {host}:{port}")
            return [
                OpenSSL_crypto.dump_certificate(OpenSSL_crypto.FILETYPE_ASN1, cert)
                for cert in chain
            ]
        finally:
            try:
                connection.shutdown()
            except Exception:
                pass
            connection.close()
            tcp_socket.close()

    def _fetch_peer_cert_chain_with_openssl(  # pragma: no cover - external OpenSSL integration
        self,
        host: str,
        port: int,
    ) -> List[bytes]:
        """Fetch peer certificate chain using OpenSSL CLI fallback.

        Args:
            host (str): TLS server hostname.
            port (int): TLS server port.

        Returns:
            List[bytes]: Certificate chain in wire order (leaf first).

        Raises:
            RuntimeError: If certificates cannot be retrieved.
        """
        process = self._run_openssl(
            [
                "s_client",
                "-connect",
                f"{host}:{port}",
                "-servername",
                host,
                "-showcerts",
            ],
            timeout=20,
        )
        output = process.stdout + process.stderr
        pem_blocks = self._TLSA_PEM_RE.findall(output)
        if not pem_blocks:
            raise RuntimeError(f"No TLS certificates returned by {host}:{port}")
        return [ssl.PEM_cert_to_DER_cert(block.decode("ascii")) for block in pem_blocks]

    def _fetch_peer_cert_chain(  # pragma: no cover - external OpenSSL integration
        self, host: str, port: int
    ) -> List[bytes]:
        """Fetch peer certificate chain as DER bytes.

        Args:
            host (str): TLS server hostname.
            port (int): TLS server port.

        Returns:
            List[bytes]: Certificate chain in wire order (leaf first).

        Raises:
            RuntimeError: If certificates cannot be retrieved.
        """
        if self._has_pyopenssl():
            return self._fetch_peer_cert_chain_with_pyopenssl(host, port)
        return self._fetch_peer_cert_chain_with_openssl(host, port)

    def _check_pkix_validation(  # pragma: no cover - external OpenSSL integration
        self, host: str, port: int
    ) -> tuple[bool, str]:
        """Check PKIX/hostname validation for a TLS endpoint.

        Args:
            host (str): TLS server hostname.
            port (int): TLS server port.

        Returns:
            tuple[bool, str]: Validation success flag and human-readable status.
        """
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection((host, port), timeout=10) as tcp_socket:
                with context.wrap_socket(tcp_socket, server_hostname=host):
                    return True, "0 (ok)"
        except ssl.SSLCertVerificationError as err:
            verify_code = getattr(err, "verify_code", 1)
            verify_message = getattr(err, "verify_message", str(err))
            return False, f"{verify_code} ({verify_message})"
        except (ssl.SSLError, OSError) as err:
            return False, str(err)

    def _extract_spki_der_with_cryptography(  # pragma: no cover - optional cryptography integration
        self,
        certificate_der: bytes,
    ) -> bytes:
        """Extract DER SPKI bytes using ``pyca/cryptography``.

        Args:
            certificate_der (bytes): DER certificate bytes.

        Returns:
            bytes: DER-encoded SubjectPublicKeyInfo bytes.

        Raises:
            RuntimeError: If SPKI extraction fails.
        """
        if not self._has_cryptography():
            raise RuntimeError("cryptography is not installed")
        try:
            certificate = cryptography_x509.load_der_x509_certificate(certificate_der)
            return certificate.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        except ValueError as err:
            raise RuntimeError(f"Failed to parse DER certificate: {err}") from err
        except Exception as err:
            raise RuntimeError(f"Failed to extract DER SPKI with cryptography: {err}") from err

    def _extract_spki_der_with_openssl(  # pragma: no cover - external OpenSSL integration
        self,
        certificate_der: bytes,
    ) -> bytes:
        """Extract DER SPKI bytes using OpenSSL CLI fallback.

        Args:
            certificate_der (bytes): DER certificate bytes.

        Returns:
            bytes: DER-encoded SubjectPublicKeyInfo bytes.

        Raises:
            RuntimeError: If SPKI extraction fails.
        """
        certificate_pem = ssl.DER_cert_to_PEM_cert(certificate_der).encode("ascii")
        pubkey_process = self._run_openssl(
            ["x509", "-pubkey", "-noout"],
            input_data=certificate_pem,
        )
        if pubkey_process.returncode != 0:
            stderr = pubkey_process.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Failed to extract certificate public key: {stderr}")
        spki_process = self._run_openssl(
            ["pkey", "-pubin", "-outform", "DER"],
            input_data=pubkey_process.stdout,
        )
        if spki_process.returncode != 0:
            stderr = spki_process.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Failed to convert public key to DER SPKI: {stderr}")
        return spki_process.stdout

    def _extract_spki_der(  # pragma: no cover - external OpenSSL integration
        self, certificate_der: bytes
    ) -> bytes:
        """Extract DER-encoded SubjectPublicKeyInfo from a certificate.

        Args:
            certificate_der (bytes): DER certificate bytes.

        Returns:
            bytes: DER-encoded SubjectPublicKeyInfo bytes.

        Raises:
            RuntimeError: If SPKI extraction fails.
        """
        if self._has_cryptography():
            return self._extract_spki_der_with_cryptography(certificate_der)
        return self._extract_spki_der_with_openssl(certificate_der)

    def _tlsa_selector_bytes(
        self,
        certificate_der: bytes,
        selector: int,
        spki_cache: Dict[bytes, bytes],
    ) -> bytes:
        """Build TLSA selector bytes for one certificate.

        Args:
            certificate_der (bytes): DER certificate bytes.
            selector (int): TLSA selector value.
            spki_cache (Dict[bytes, bytes]): Cache for extracted SPKI bytes.

        Returns:
            bytes: Selector bytes for digest/exact comparison.

        Raises:
            ValueError: If selector is unsupported.
            RuntimeError: If SPKI extraction fails.
        """
        if selector == 0:
            return certificate_der
        if selector == 1:
            if certificate_der not in spki_cache:
                spki_cache[certificate_der] = self._extract_spki_der(certificate_der)
            return spki_cache[certificate_der]
        raise ValueError(f"Unsupported TLSA selector {selector}")

    def _tlsa_entry_matches_certificate(
        self,
        entry: tuple[int, int, int, str],
        certificate_der: bytes,
        spki_cache: Dict[bytes, bytes],
    ) -> bool:
        """Evaluate whether a TLSA entry matches one certificate.

        Args:
            entry (tuple[int, int, int, str]): TLSA entry tuple.
            certificate_der (bytes): DER certificate bytes.
            spki_cache (Dict[bytes, bytes]): Cache for extracted SPKI bytes.

        Returns:
            bool: True when the TLSA entry matches this certificate.

        Raises:
            ValueError: If selector or matching type is unsupported.
            RuntimeError: If SPKI extraction fails.
        """
        _usage, selector, matching_type, association = entry
        selected_data = self._tlsa_selector_bytes(certificate_der, selector, spki_cache)
        normalized_association = self._normalize_tlsa_association(association)

        if matching_type == 0:
            return selected_data.hex().lower() == normalized_association
        if matching_type == 1:
            return hashlib.sha256(selected_data).hexdigest() == normalized_association
        if matching_type == 2:
            return hashlib.sha512(selected_data).hexdigest() == normalized_association
        raise ValueError(f"Unsupported TLSA matching_type {matching_type}")

    def _verify_tlsa_bindings(
        self,
        records: Dict[str, List[tuple[int, int, int, str]]],
    ) -> Dict[str, object]:  # pragma: no cover - external TLS endpoint integration
        """Verify TLSA records against live TLS certificates.

        Args:
            records (Dict[str, List[tuple[int, int, int, str]]]): TLSA records keyed by owner name.

        Returns:
            Dict[str, object]: Verification details containing mismatches/errors.
        """
        unsupported_names: Dict[str, str] = {}
        endpoint_errors: Dict[str, str] = {}
        unsupported_entries: Dict[str, List[tuple[int, int, int, str]]] = {}
        pkix_failures: Dict[str, Dict[str, object]] = {}
        certificate_mismatches: Dict[str, List[tuple[int, int, int, str]]] = {}

        for name, entries in records.items():
            parsed = self._parse_tlsa_owner_name(name)
            if parsed is None:
                unsupported_names[name] = "TLSA owner name must be _port._transport.hostname"
                continue
            port, transport, host = parsed
            if transport != "tcp":
                unsupported_names[name] = f"Unsupported TLSA transport '{transport}'"
                continue

            try:
                certificate_chain = self._fetch_peer_cert_chain(host, port)
            except Exception as err:
                endpoint_errors[name] = str(err)
                continue

            try:
                pkix_valid, pkix_status = self._check_pkix_validation(host, port)
            except Exception as err:
                endpoint_errors[name] = str(err)
                continue
            spki_cache: Dict[bytes, bytes] = {}
            mismatched_entries: List[tuple[int, int, int, str]] = []
            invalid_entries: List[tuple[int, int, int, str]] = []

            for entry in entries:
                usage, selector, matching_type, _association = entry
                if (
                    usage not in {0, 1, 2, 3}
                    or selector not in {0, 1}
                    or matching_type not in {0, 1, 2}
                ):
                    invalid_entries.append(entry)
                    continue

                if usage in {0, 1} and not pkix_valid:
                    pkix_failures[name] = {
                        "status": pkix_status,
                        "usage": usage,
                    }
                    mismatched_entries.append(entry)
                    continue

                if usage in {1, 3}:
                    candidate_certificates = certificate_chain[:1]
                else:
                    candidate_certificates = certificate_chain[1:]

                if not candidate_certificates:
                    mismatched_entries.append(entry)
                    continue

                matched = False
                for certificate_der in candidate_certificates:
                    try:
                        if self._tlsa_entry_matches_certificate(entry, certificate_der, spki_cache):
                            matched = True
                            break
                    except ValueError:
                        invalid_entries.append(entry)
                        matched = False
                        break
                    except Exception as err:
                        endpoint_errors[name] = str(err)
                        matched = False
                        break

                if not matched and name not in endpoint_errors:
                    mismatched_entries.append(entry)

            if invalid_entries:
                unsupported_entries[name] = invalid_entries
            if mismatched_entries:
                certificate_mismatches[name] = mismatched_entries

        return {
            "unsupported_names": unsupported_names,
            "unsupported_entries": unsupported_entries,
            "endpoint_errors": endpoint_errors,
            "pkix_failures": pkix_failures,
            "certificate_mismatches": certificate_mismatches,
        }

    def _dnssec_unverified_names(self, dnssec_status: Dict[str, Optional[bool]]) -> List[str]:
        """Return names lacking DNSSEC-authenticated TLSA answers.

        Args:
            dnssec_status (Dict[str, Optional[bool]]): DNSSEC status keyed by TLSA owner name.

        Returns:
            List[str]: Names whose TLSA records are not DNSSEC-authenticated.
        """
        return sorted(name for name, status in dnssec_status.items() if status is not True)

    def _should_run_live_tlsa_verification(self) -> bool:
        """Return whether live TLS verification should run for this resolver.

        Returns:
            bool: True when the resolver opts in to live TLS verification.
        """
        return bool(getattr(self.resolver, "supports_live_tls_verification", False))

    def check_tlsa(self) -> RecordCheck:
        """Validate TLSA records for the configured provider.

        Returns:
            RecordCheck: Result of the TLSA validation.

        Raises:
            ValueError: If the provider does not define TLSA requirements.
        """
        if not self.provider.tlsa:
            raise ValueError("TLSA configuration not available for provider")

        try:
            missing, extra, expected, found, dnssec_status = self._evaluate_tlsa_records(
                self.provider.tlsa.required
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("TLSA", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {
                    "expected": expected,
                    "found": found,
                    "dnssec_status": dnssec_status,
                }
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA records do not exactly match required configuration",
                    details,
                )
            success_message = "TLSA records match required configuration"
        else:
            if missing:
                return RecordCheck.fail(
                    "TLSA",
                    "Missing required TLSA records",
                    {
                        "missing": missing,
                        "expected": expected,
                        "found": found,
                        "dnssec_status": dnssec_status,
                    },
                )
            success_message = "Required TLSA records present"

        dnssec_unverified = self._dnssec_unverified_names(dnssec_status)
        if dnssec_unverified:
            return RecordCheck.fail(
                "TLSA",
                "TLSA records are not DNSSEC-authenticated",
                {
                    "unverified": dnssec_unverified,
                    "dnssec_status": dnssec_status,
                    "expected": expected,
                    "found": found,
                },
            )

        if self._should_run_live_tlsa_verification():
            verification = self._verify_tlsa_bindings(expected)
            if verification["endpoint_errors"]:
                return RecordCheck.unknown(
                    "TLSA",
                    "TLSA certificate verification failed",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                )
            if verification["unsupported_names"] or verification["unsupported_entries"]:
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA DANE verification unsupported for one or more records",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                )
            if verification["certificate_mismatches"]:
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA records do not match presented TLS certificates",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                )

        if extra:
            return RecordCheck.warn(
                "TLSA",
                "Additional TLSA records present; required records found",
                {
                    "extra": extra,
                    "found": found,
                    "expected": expected,
                    "dnssec_status": dnssec_status,
                },
            )

        return RecordCheck.pass_(
            "TLSA",
            success_message,
            {
                "expected": expected,
                "dnssec_status": dnssec_status,
            },
        )

    def check_tlsa_optional(self) -> RecordCheck:
        """Validate optional TLSA records for the configured provider.

        Returns:
            RecordCheck: Result of the optional TLSA validation.

        Raises:
            ValueError: If the provider does not define TLSA requirements.
        """
        if not self.provider.tlsa:
            raise ValueError("TLSA configuration not available for provider")

        optional_records = self.provider.tlsa.optional
        if not optional_records:
            return RecordCheck.pass_(
                "TLSA",
                "No optional TLSA records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found, dnssec_status = self._evaluate_tlsa_records(
                optional_records
            )
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "TLSA",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck.fail(
                "TLSA",
                "TLSA optional records mismatched",
                {
                    "missing": missing,
                    "extra": extra,
                    "found": found,
                    "expected": expected,
                    "dnssec_status": dnssec_status,
                },
                optional=True,
            )
        if missing:
            return RecordCheck.warn(
                "TLSA",
                "TLSA optional records missing",
                {
                    "missing": missing,
                    "found": found,
                    "expected": expected,
                    "dnssec_status": dnssec_status,
                },
                optional=True,
            )

        dnssec_unverified = self._dnssec_unverified_names(dnssec_status)
        if dnssec_unverified:
            return RecordCheck.fail(
                "TLSA",
                "TLSA optional records are not DNSSEC-authenticated",
                {
                    "unverified": dnssec_unverified,
                    "dnssec_status": dnssec_status,
                    "expected": expected,
                    "found": found,
                },
                optional=True,
            )

        if self._should_run_live_tlsa_verification():
            verification = self._verify_tlsa_bindings(expected)
            if verification["endpoint_errors"]:
                return RecordCheck.unknown(
                    "TLSA",
                    "TLSA certificate verification failed",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                    optional=True,
                )
            if verification["unsupported_names"] or verification["unsupported_entries"]:
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA optional records use unsupported DANE settings",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                    optional=True,
                )
            if verification["certificate_mismatches"]:
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA optional records do not match presented TLS certificates",
                    {
                        **verification,
                        "expected": expected,
                        "found": found,
                    },
                    optional=True,
                )

        return RecordCheck.pass_(
            "TLSA",
            "TLSA optional records present",
            {
                "expected": expected,
                "dnssec_status": dnssec_status,
            },
            optional=True,
        )

    def _evaluate_tlsa_match_rules(self, rules: Dict[str, "TLSAMatchRule"]) -> tuple[
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, Optional[bool]],
    ]:
        """Evaluate deprecated/forbidden TLSA rules.

        Args:
            rules (Dict[str, TLSAMatchRule]): Match rules keyed by record name.

        Returns:
            tuple[Dict[str, List[tuple[int, int, int, str]]], ...]: Matched, expected, found, and
                DNSSEC authentication status keyed by record name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        matched: Dict[str, List[tuple[int, int, int, str]]] = {}
        expected: Dict[str, List[tuple[int, int, int, str]]] = {}
        found: Dict[str, List[tuple[int, int, int, str]]] = {}
        dnssec_status: Dict[str, Optional[bool]] = {}
        for name, rule in rules.items():
            lookup_name = self._normalize_record_name(name)
            if hasattr(self.resolver, "get_tlsa_with_status"):
                found_entries_raw, authenticated = self.resolver.get_tlsa_with_status(lookup_name)
            else:
                found_entries_raw = self.resolver.get_tlsa(lookup_name)
                authenticated = None
            dnssec_status[lookup_name] = authenticated
            found_entries = sorted(
                self._normalize_tlsa_entry(usage, selector, matching_type, certificate_association)
                for usage, selector, matching_type, certificate_association in found_entries_raw
            )
            expected_entries = sorted(
                self._normalize_tlsa_entry(
                    entry.usage,
                    entry.selector,
                    entry.matching_type,
                    entry.certificate_association,
                )
                for entry in rule.entries
            )
            found[lookup_name] = found_entries
            expected[lookup_name] = expected_entries
            if rule.match == "any":
                if found_entries:
                    matched[lookup_name] = found_entries
                continue
            overlap = sorted(set(expected_entries) & set(found_entries))
            if overlap:
                matched[lookup_name] = overlap
        return matched, expected, found, dnssec_status

    def _check_tlsa_negative(self, rules: Dict[str, "TLSAMatchRule"], *, scope: str) -> RecordCheck:
        """Run deprecated/forbidden checks for TLSA records.

        Args:
            rules (Dict[str, TLSAMatchRule]): Match rules keyed by record name.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific TLSA match result.
        """
        if not rules:
            return RecordCheck.pass_(
                "TLSA",
                f"No {scope} TLSA records configured",
                {},
                scope=scope,
            )
        try:
            matched, expected, found, dnssec_status = self._evaluate_tlsa_match_rules(rules)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "TLSA",
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        if matched:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                "TLSA",
                f"{scope.capitalize()} TLSA records are present",
                {
                    "matched": matched,
                    "expected": expected,
                    "found": found,
                    "dnssec_status": dnssec_status,
                },
                scope=scope,
            )
        return RecordCheck.pass_(
            "TLSA",
            f"No {scope} TLSA records present",
            {"expected": expected, "dnssec_status": dnssec_status},
            scope=scope,
        )

    def check_tlsa_deprecated(self) -> RecordCheck:
        """Validate deprecated TLSA records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated TLSA validation.

        Raises:
            ValueError: If the provider does not define TLSA requirements.
        """
        if not self.provider.tlsa:
            raise ValueError("TLSA configuration not available for provider")
        return self._check_tlsa_negative(self.provider.tlsa.deprecated, scope="deprecated")

    def check_tlsa_forbidden(self) -> RecordCheck:
        """Validate forbidden TLSA records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden TLSA validation.

        Raises:
            ValueError: If the provider does not define TLSA requirements.
        """
        if not self.provider.tlsa:
            raise ValueError("TLSA configuration not available for provider")
        return self._check_tlsa_negative(self.provider.tlsa.forbidden, scope="forbidden")
