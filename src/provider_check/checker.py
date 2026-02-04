"""Core DNS validation logic."""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
from typing import Dict, Iterable, List, Optional

from .dns_resolver import DnsLookupError, DnsResolver
from .provider_config import ProviderConfig

LOGGER = logging.getLogger(__name__)
_SPF_QUALIFIERS = {"-", "~", "?"}


@dataclasses.dataclass
class RecordCheck:
    """Represent the outcome of a DNS record validation.

    Attributes:
        record_type (str): DNS record type being validated (e.g., MX, SPF, DKIM).
        status (str): Result status (PASS, WARN, FAIL, or UNKNOWN).
        message (str): Human-readable summary of the outcome.
        details (Dict[str, object]): Structured details for debugging or output.
        optional (bool): Whether the check is for optional records.
    """

    record_type: str
    status: str  # PASS | WARN | FAIL
    message: str
    details: Dict[str, object]
    optional: bool = False


class DNSChecker:
    """Validate provider-specific DNS records for a domain.

    Attributes:
        domain (str): Normalized domain being checked.
        provider (ProviderConfig): Provider configuration used for validation.
        resolver (DnsResolver): DNS resolver used for lookups.
        strict (bool): Whether to enforce exact matches with no extras.
        dmarc_policy (str): DMARC policy to require (p=).
        dmarc_rua_mailto (List[str]): Required rua mailto URIs.
        dmarc_ruf_mailto (List[str]): Required ruf mailto URIs.
        dmarc_required_tags (Dict[str, str]): Required DMARC tag overrides.
        spf_policy (str): SPF policy enforcement ("hardfail" or "softfail").
        additional_spf_includes (List[str]): Additional SPF include mechanisms.
        additional_spf_ip4 (List[str]): Additional SPF ip4 mechanisms.
        additional_spf_ip6 (List[str]): Additional SPF ip6 mechanisms.
        additional_txt (Dict[str, Iterable[str]]): Additional required TXT records.
        additional_txt_verification (Dict[str, Iterable[str]]): Extra TXT verification records.
        skip_txt_verification (bool): Skip provider-required TXT verification checks.
    """

    def __init__(
        self,
        domain: str,
        provider: ProviderConfig,
        resolver: Optional[DnsResolver] = None,
        *,
        strict: bool = False,
        dmarc_rua_mailto: Optional[Iterable[str]] = None,
        dmarc_ruf_mailto: Optional[Iterable[str]] = None,
        dmarc_policy: Optional[str] = None,
        dmarc_required_tags: Optional[Dict[str, str]] = None,
        spf_policy: str = "hardfail",
        additional_spf_includes: Optional[Iterable[str]] = None,
        additional_spf_ip4: Optional[Iterable[str]] = None,
        additional_spf_ip6: Optional[Iterable[str]] = None,
        additional_txt: Optional[Dict[str, Iterable[str]]] = None,
        additional_txt_verification: Optional[Dict[str, Iterable[str]]] = None,
        skip_txt_verification: bool = False,
    ) -> None:
        """Initialize a DNSChecker for a domain and provider.

        Args:
            domain (str): Domain to validate.
            provider (ProviderConfig): Provider configuration to enforce.
            resolver (Optional[DnsResolver]): DNS resolver to use.
            strict (bool): If True, require exact matches and no extras.
            dmarc_rua_mailto (Optional[Iterable[str]]): Required DMARC rua mailto URIs.
            dmarc_ruf_mailto (Optional[Iterable[str]]): Required DMARC ruf mailto URIs.
            dmarc_policy (Optional[str]): Override DMARC policy (p=).
            dmarc_required_tags (Optional[Dict[str, str]]): DMARC tag overrides to require.
            spf_policy (str): SPF policy ("hardfail" -> -all, "softfail" -> ~all).
            additional_spf_includes (Optional[Iterable[str]]): Additional SPF include entries.
            additional_spf_ip4 (Optional[Iterable[str]]): Additional SPF ip4 entries.
            additional_spf_ip6 (Optional[Iterable[str]]): Additional SPF ip6 entries.
            additional_txt (Optional[Dict[str, Iterable[str]]]): Additional required TXT values.
            additional_txt_verification (Optional[Dict[str, Iterable[str]]]): TXT verification values.
            skip_txt_verification (bool): Skip provider-required TXT verification checks.

        Raises:
            ValueError: If a DMARC mailto value is empty after normalization.
        """
        self.domain = domain.lower().strip()
        self.provider = provider
        self.resolver = resolver or DnsResolver()
        self.strict = strict

        dmarc_default_policy = "reject"
        if provider.dmarc:
            dmarc_default_policy = provider.dmarc.default_policy

        self.dmarc_policy = (dmarc_policy or dmarc_default_policy).lower()
        self.dmarc_rua_mailto = self._normalize_mailto_list(dmarc_rua_mailto or [])
        self._dmarc_rua_override = bool(self.dmarc_rua_mailto)
        self.dmarc_ruf_mailto = self._normalize_mailto_list(dmarc_ruf_mailto or [])
        self._dmarc_ruf_override = bool(self.dmarc_ruf_mailto)
        self.dmarc_required_tags: Dict[str, str] = {}
        if provider.dmarc:
            self.dmarc_required_tags = {
                str(key).lower(): str(value) for key, value in provider.dmarc.required_tags.items()
            }
        if dmarc_required_tags:
            for key, value in dmarc_required_tags.items():
                self.dmarc_required_tags[str(key).lower()] = str(value)
        self.spf_policy = spf_policy.lower()
        self.additional_spf_includes = list(additional_spf_includes or [])
        self.additional_spf_ip4 = list(additional_spf_ip4 or [])
        self.additional_spf_ip6 = list(additional_spf_ip6 or [])
        self.additional_txt = {
            str(name): [str(value) for value in values]
            for name, values in (additional_txt or {}).items()
        }
        self.additional_txt_verification = {
            str(name): [str(value) for value in values]
            for name, values in (additional_txt_verification or {}).items()
        }
        self.skip_txt_verification = skip_txt_verification

    def run_checks(self) -> List[RecordCheck]:
        """Run all enabled DNS checks for the configured provider.

        Returns:
            List[RecordCheck]: Ordered list of check results.
        """
        LOGGER.info(
            "Running DNS checks for %s with provider %s (v%s)",
            self.domain,
            self.provider.name,
            self.provider.version,
        )
        checks: List[tuple[str, callable]] = []
        if self.provider.mx:
            checks.append(("MX", self.check_mx))
        if self.provider.spf:
            checks.append(("SPF", self.check_spf))
        if self.provider.dkim:
            checks.append(("DKIM", self.check_dkim))
        if self.provider.a:
            if self.provider.a.records:
                checks.append(("A", self.check_a))
            if self.provider.a.records_optional:
                checks.append(("A", self.check_a_optional))
        if self.provider.aaaa:
            if self.provider.aaaa.records:
                checks.append(("AAAA", self.check_aaaa))
            if self.provider.aaaa.records_optional:
                checks.append(("AAAA", self.check_aaaa_optional))
        if self.provider.cname:
            if self.provider.cname.records:
                checks.append(("CNAME", self.check_cname))
            if self.provider.cname.records_optional:
                checks.append(("CNAME", self.check_cname_optional))
        if self.provider.caa:
            if self.provider.caa.records:
                checks.append(("CAA", self.check_caa))
            if self.provider.caa.records_optional:
                checks.append(("CAA", self.check_caa_optional))
        if self.provider.srv:
            if self.provider.srv.records:
                checks.append(("SRV", self.check_srv))
            if self.provider.srv.records_optional:
                checks.append(("SRV", self.check_srv_optional))
        if self.provider.txt or self.additional_txt or self.additional_txt_verification:
            checks.append(("TXT", self.check_txt))
        if self.provider.dmarc:
            checks.append(("DMARC", self.check_dmarc))

        if not checks:
            LOGGER.info("No checks enabled for %s", self.domain)
            return []

        LOGGER.debug("Enabled checks: %s", ", ".join(name for name, _check in checks))
        results: List[RecordCheck] = []
        for name, check in checks:
            LOGGER.debug("Starting %s check", name)
            result = check()
            LOGGER.info("%s: %s - %s", result.record_type, result.status, result.message)
            if result.details:
                LOGGER.debug("%s details: %s", result.record_type, result.details)
            results.append(result)
        return results

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Normalize a hostname to lowercase and ensure a trailing dot.

        Args:
            host (str): Hostname to normalize.

        Returns:
            str: Normalized hostname ending in a dot.
        """
        return host.rstrip(".").lower() + "."

    @staticmethod
    def _strip_spf_qualifier(token: str) -> tuple[str, str]:
        """Split an SPF token into base value and qualifier.

        Args:
            token (str): SPF token (e.g., "-all", "~ip4:1.2.3.4").

        Returns:
            tuple[str, str]: (base, qualifier) where qualifier may be empty.
        """
        if token and token[0] in "+-~?":
            return token[1:], token[0]
        return token, ""

    def _normalize_txt_name(self, name: str) -> str:
        """Normalize a TXT record name to a fully qualified domain.

        Args:
            name (str): TXT record name or template.

        Returns:
            str: Fully qualified TXT record name without trailing dot.
        """
        trimmed = name.strip()
        if trimmed == "@":
            return self.domain
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if trimmed.endswith("."):
            return trimmed[:-1]
        if "." in trimmed:
            return trimmed
        return f"{trimmed}.{self.domain}"

    def _normalize_record_name(self, name: str) -> str:
        """Normalize a record name to a fully qualified domain.

        Args:
            name (str): Record name or template.

        Returns:
            str: Fully qualified record name without trailing dot.
        """
        trimmed = name.strip()
        if trimmed == "@":
            return self.domain
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if trimmed.endswith("."):
            return trimmed[:-1]
        if trimmed.endswith(self.domain):
            return trimmed
        return f"{trimmed}.{self.domain}"

    @staticmethod
    def _normalize_address_value(value: str) -> str:
        """Normalize an IP address value for comparison.

        Args:
            value (str): Raw IP address value.

        Returns:
            str: Normalized IP address string.
        """
        trimmed = str(value).strip()
        try:
            return ipaddress.ip_address(trimmed).compressed
        except ValueError:
            return trimmed.lower()

    @staticmethod
    def _normalize_caa_value(value: str, tag: str) -> str:
        """Normalize a CAA value for comparison.

        Args:
            value (str): Raw CAA value.
            tag (str): CAA tag associated with the value.

        Returns:
            str: Normalized CAA value.
        """
        normalized = " ".join(str(value).split()).strip()
        tag_normalized = str(tag).strip().lower()
        if tag_normalized in {"issue", "issuewild"}:
            return normalized.lower()
        return normalized

    def _normalize_caa_entry(self, flags: int, tag: str, value: str) -> tuple[int, str, str]:
        """Normalize a CAA entry for comparison.

        Args:
            flags (int): CAA flags value.
            tag (str): CAA tag value.
            value (str): CAA value string.

        Returns:
            tuple[int, str, str]: Normalized tuple for matching.
        """
        normalized_tag = str(tag).strip().lower()
        return (
            int(flags),
            normalized_tag,
            self._normalize_caa_value(str(value), normalized_tag),
        )

    def _normalize_mailto(self, value: str) -> str:
        """Normalize a DMARC mailto value.

        Args:
            value (str): Mailto value with or without "mailto:" prefix.

        Returns:
            str: Normalized mailto URI in lowercase.

        Raises:
            ValueError: If the mailto value is empty.
        """
        trimmed = value.strip()
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if not trimmed:
            raise ValueError("DMARC mailto value must not be empty")
        if trimmed.lower().startswith("mailto:"):
            address = trimmed[len("mailto:") :].strip()
        else:
            address = trimmed
        if not address:
            raise ValueError("DMARC mailto value must include an address")
        return f"mailto:{address}".lower()

    def _normalize_mailto_list(self, values: Iterable[str]) -> List[str]:
        """Normalize and de-duplicate a list of mailto values.

        Args:
            values (Iterable[str]): Mailto values to normalize.

        Returns:
            List[str]: Normalized, de-duplicated mailto URIs.
        """
        normalized: List[str] = []
        for value in values:
            normalized_value = self._normalize_mailto(str(value))
            if normalized_value not in normalized:
                normalized.append(normalized_value)
        return normalized

    def _effective_required_rua(self) -> List[str]:
        """Determine the required rua mailto values.

        Returns:
            List[str]: Required rua mailto URIs after overrides.
        """
        if not self.provider.dmarc:
            return []
        if self._dmarc_rua_override:
            return list(self.dmarc_rua_mailto)
        return self._normalize_mailto_list(self.provider.dmarc.required_rua)

    def _effective_required_ruf(self) -> List[str]:
        """Determine the required ruf mailto values.

        Returns:
            List[str]: Required ruf mailto URIs after overrides.
        """
        if not self.provider.dmarc:
            return []
        if self._dmarc_ruf_override:
            return list(self.dmarc_ruf_mailto)
        return self._normalize_mailto_list(self.provider.dmarc.required_ruf)

    def _rua_required(self, required_rua: List[str]) -> bool:
        """Check whether rua values must be present.

        Args:
            required_rua (List[str]): Required rua entries.

        Returns:
            bool: True if rua is required.
        """
        if not self.provider.dmarc:
            return False
        if self._dmarc_rua_override:
            return True
        return self.provider.dmarc.rua_required or bool(required_rua)

    def _ruf_required(self, required_ruf: List[str]) -> bool:
        """Check whether ruf values must be present.

        Args:
            required_ruf (List[str]): Required ruf entries.

        Returns:
            bool: True if ruf is required.
        """
        if not self.provider.dmarc:
            return False
        if self._dmarc_ruf_override:
            return True
        return self.provider.dmarc.ruf_required or bool(required_ruf)

    def check_mx(self) -> RecordCheck:
        """Validate MX records for the configured provider.

        Returns:
            RecordCheck: Result of the MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")

        try:
            mx_records = self.resolver.get_mx(self.domain)
        except DnsLookupError as err:
            return RecordCheck("MX", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
        expected = {self._normalize_host(host) for host in self.provider.mx.hosts}
        found: set[str] = set()
        found_priorities: Dict[str, List[int]] = {}

        for record in mx_records:
            if isinstance(record, tuple):
                host, preference = record
            else:
                host, preference = record, None
            normalized = self._normalize_host(str(host))
            found.add(normalized)
            if preference is not None:
                found_priorities.setdefault(normalized, []).append(int(preference))

        if not found:
            return RecordCheck("MX", "FAIL", "No MX records found", {"expected": sorted(expected)})

        missing = expected - found
        extra = found - expected

        expected_priorities = {
            self._normalize_host(host): int(priority)
            for host, priority in self.provider.mx.priorities.items()
        }
        mismatched: Dict[str, Dict[str, object]] = {}
        for host, priority in expected_priorities.items():
            found_values = found_priorities.get(host, [])
            if found_values and priority in found_values:
                continue
            if host in found:
                mismatched[host] = {"expected": priority, "found": sorted(found_values)}

        if self.strict:
            if missing or extra or mismatched:
                message = "MX records do not exactly match required configuration"
                details: Dict[str, object] = {"expected": sorted(expected), "found": sorted(found)}
                if mismatched:
                    details["mismatched"] = mismatched
                if extra:
                    details["extra"] = sorted(extra)
                return RecordCheck("MX", "FAIL", message, details)
            return RecordCheck(
                "MX", "PASS", "MX records match required configuration", {"found": sorted(found)}
            )

        if missing:
            return RecordCheck(
                "MX",
                "FAIL",
                "Missing required MX host(s)",
                {"missing": sorted(missing), "found": sorted(found)},
            )
        if mismatched:
            details = {"mismatched": mismatched, "found": sorted(found)}
            if extra:
                details["extra"] = sorted(extra)
            return RecordCheck("MX", "WARN", "MX priorities differ from expected", details)
        if extra:
            return RecordCheck(
                "MX",
                "WARN",
                "Additional MX hosts present; required hosts found",
                {"extra": sorted(extra), "found": sorted(found)},
            )
        return RecordCheck("MX", "PASS", "Required MX records present", {"found": sorted(found)})

    def _evaluate_address_records(
        self,
        records: Dict[str, List[str]],
        lookup,
    ) -> tuple[
        Dict[str, List[str]],
        Dict[str, List[str]],
        Dict[str, List[str]],
        Dict[str, List[str]],
    ]:
        """Evaluate A/AAAA records and return missing/extra details.

        Args:
            records (Dict[str, List[str]]): Expected records mapping.
            lookup (callable): DNS lookup function for the record type.

        Returns:
            tuple[Dict[str, List[str]], ...]: Missing, extra, expected, and found values keyed by
                record name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[str]] = {}
        extra: Dict[str, List[str]] = {}
        expected: Dict[str, List[str]] = {}
        found: Dict[str, List[str]] = {}

        for name, values in records.items():
            lookup_name = self._normalize_record_name(name)
            expected_values = [self._normalize_address_value(value) for value in values]
            expected[lookup_name] = expected_values

            found_values = [self._normalize_address_value(value) for value in lookup(lookup_name)]
            found[lookup_name] = found_values

            expected_set = set(expected_values)
            found_set = set(found_values)
            missing_values = sorted(expected_set - found_set)
            extra_values = sorted(found_set - expected_set)
            if missing_values:
                missing[lookup_name] = missing_values
            if extra_values:
                extra[lookup_name] = extra_values

        return missing, extra, expected, found

    def check_a(self) -> RecordCheck:
        """Validate A records for the configured provider.

        Returns:
            RecordCheck: Result of the A validation.

        Raises:
            ValueError: If the provider does not define A requirements.
        """
        if not self.provider.a:
            raise ValueError("A configuration not available for provider")

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                self.provider.a.records, self.resolver.get_a
            )
        except DnsLookupError as err:
            return RecordCheck("A", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck(
                    "A",
                    "FAIL",
                    "A records do not exactly match required configuration",
                    details,
                )
            return RecordCheck(
                "A",
                "PASS",
                "A records match required configuration",
                {"records": expected},
            )

        if missing:
            return RecordCheck(
                "A",
                "FAIL",
                "Missing required A records",
                {"missing": missing, "expected": expected, "found": found},
            )
        if extra:
            return RecordCheck(
                "A",
                "WARN",
                "Additional A records present; required values found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck(
            "A",
            "PASS",
            "Required A records present",
            {"records": expected},
        )

    def check_a_optional(self) -> RecordCheck:
        """Validate optional A records for the configured provider.

        Returns:
            RecordCheck: Result of the optional A validation.

        Raises:
            ValueError: If the provider does not define A requirements.
        """
        if not self.provider.a:
            raise ValueError("A configuration not available for provider")

        records_optional = self.provider.a.records_optional
        if not records_optional:
            return RecordCheck(
                "A",
                "PASS",
                "No optional A records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                records_optional, self.resolver.get_a
            )
        except DnsLookupError as err:
            return RecordCheck(
                "A",
                "UNKNOWN",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck(
                "A",
                "FAIL",
                "A optional records mismatched",
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck(
                "A",
                "WARN",
                "A optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck(
            "A",
            "PASS",
            "A optional records present",
            {"records": expected},
            optional=True,
        )

    def check_aaaa(self) -> RecordCheck:
        """Validate AAAA records for the configured provider.

        Returns:
            RecordCheck: Result of the AAAA validation.

        Raises:
            ValueError: If the provider does not define AAAA requirements.
        """
        if not self.provider.aaaa:
            raise ValueError("AAAA configuration not available for provider")

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                self.provider.aaaa.records, self.resolver.get_aaaa
            )
        except DnsLookupError as err:
            return RecordCheck("AAAA", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck(
                    "AAAA",
                    "FAIL",
                    "AAAA records do not exactly match required configuration",
                    details,
                )
            return RecordCheck(
                "AAAA",
                "PASS",
                "AAAA records match required configuration",
                {"records": expected},
            )

        if missing:
            return RecordCheck(
                "AAAA",
                "FAIL",
                "Missing required AAAA records",
                {"missing": missing, "expected": expected, "found": found},
            )
        if extra:
            return RecordCheck(
                "AAAA",
                "WARN",
                "Additional AAAA records present; required values found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck(
            "AAAA",
            "PASS",
            "Required AAAA records present",
            {"records": expected},
        )

    def check_aaaa_optional(self) -> RecordCheck:
        """Validate optional AAAA records for the configured provider.

        Returns:
            RecordCheck: Result of the optional AAAA validation.

        Raises:
            ValueError: If the provider does not define AAAA requirements.
        """
        if not self.provider.aaaa:
            raise ValueError("AAAA configuration not available for provider")

        records_optional = self.provider.aaaa.records_optional
        if not records_optional:
            return RecordCheck(
                "AAAA",
                "PASS",
                "No optional AAAA records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                records_optional, self.resolver.get_aaaa
            )
        except DnsLookupError as err:
            return RecordCheck(
                "AAAA",
                "UNKNOWN",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck(
                "AAAA",
                "FAIL",
                "AAAA optional records mismatched",
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck(
                "AAAA",
                "WARN",
                "AAAA optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck(
            "AAAA",
            "PASS",
            "AAAA optional records present",
            {"records": expected},
            optional=True,
        )

    def _build_expected_spf(self) -> str:
        """Build the expected SPF record string.

        Returns:
            str: Expected SPF record value.

        Raises:
            ValueError: If the provider does not define SPF requirements.
        """
        if not self.provider.spf:
            raise ValueError("SPF configuration not available for provider")

        spf_config = self.provider.spf
        if self.strict and spf_config.strict_record:
            return spf_config.strict_record

        tokens: List[str] = ["v=spf1"]
        tokens.extend(f"include:{value}" for value in spf_config.required_includes)
        tokens.extend(spf_config.required_mechanisms)
        if not self.strict:
            tokens.extend(f"include:{value}" for value in self.additional_spf_includes)
            tokens.extend(f"ip4:{value}" for value in self.additional_spf_ip4)
            tokens.extend(f"ip6:{value}" for value in self.additional_spf_ip6)
        if spf_config.required_modifiers:
            for key in sorted(spf_config.required_modifiers.keys()):
                tokens.append(f"{key}={spf_config.required_modifiers[key]}")
        policy_token = "-all" if self.spf_policy == "hardfail" else "~all"
        tokens.append(policy_token)
        return " ".join(tokens)

    def check_spf(self) -> RecordCheck:
        """Validate SPF records for the configured provider.

        Returns:
            RecordCheck: Result of the SPF validation.

        Raises:
            ValueError: If the provider does not define SPF requirements.
        """
        if not self.provider.spf:
            raise ValueError("SPF configuration not available for provider")

        spf_config = self.provider.spf
        try:
            txt_records = self.resolver.get_txt(self.domain)
        except DnsLookupError as err:
            return RecordCheck("SPF", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
        spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]

        if not spf_records:
            return RecordCheck(
                "SPF",
                "FAIL",
                "No SPF record found",
                {"expected": self._build_expected_spf()},
            )

        if len(spf_records) > 1:
            return RecordCheck(
                "SPF",
                "FAIL",
                "Multiple SPF records found",
                {"found": spf_records},
            )

        expected = self._build_expected_spf()
        record = spf_records[0]
        normalized = " ".join(record.split())
        if self.strict:
            if normalized.lower() == expected.lower():
                return RecordCheck(
                    "SPF", "PASS", "SPF record matches strict setup", {"record": record}
                )
            return RecordCheck(
                "SPF",
                "FAIL",
                "SPF record does not match strict configuration",
                {"expected": expected, "found": record},
            )

        required_includes = {f"include:{value.lower()}" for value in spf_config.required_includes}
        allowed_includes = required_includes | {
            f"include:{value.lower()}" for value in self.additional_spf_includes
        }

        tokens = normalized.lower().split()
        mechanisms: List[str] = []
        modifiers: Dict[str, str] = {}
        for token in tokens:
            if "=" in token:
                key, value = token.split("=", 1)
                modifiers[key.lower()] = value
            else:
                mechanisms.append(token)

        include_tokens: List[str] = []
        ip4_tokens: List[str] = []
        ip6_tokens: List[str] = []
        other_mechanisms: List[str] = []
        for token in mechanisms:
            base, _ = self._strip_spf_qualifier(token)
            if base.startswith("include:"):
                include_tokens.append(base)
            elif base.startswith("ip4:"):
                ip4_tokens.append(base)
            elif base.startswith("ip6:"):
                ip6_tokens.append(base)
            else:
                other_mechanisms.append(token)

        includes = set(include_tokens)
        has_required_includes = required_includes.issubset(includes)
        policy_required_token = "-all" if self.spf_policy == "hardfail" else "~all"
        policy_ok = policy_required_token in mechanisms

        required_mechanisms = [value.lower() for value in spf_config.required_mechanisms]
        allowed_mechanisms = [value.lower() for value in spf_config.allowed_mechanisms]
        required_modifiers = {
            key.lower(): value.lower() for key, value in spf_config.required_modifiers.items()
        }
        advanced_checks = bool(required_mechanisms or allowed_mechanisms)

        mechanism_bases_present = {self._strip_spf_qualifier(token)[0] for token in mechanisms}
        mechanism_exact_present = {
            f"{qualifier}{base}"
            for token in mechanisms
            for base, qualifier in [self._strip_spf_qualifier(token)]
            if qualifier in _SPF_QUALIFIERS
        }

        required_base = set()
        required_exact = set()
        for token in required_mechanisms:
            base, qualifier = self._strip_spf_qualifier(token)
            if qualifier in _SPF_QUALIFIERS:
                required_exact.add(f"{qualifier}{base}")
            else:
                required_base.add(base)

        required_mechanisms_ok = required_base.issubset(
            mechanism_bases_present
        ) and required_exact.issubset(mechanism_exact_present)
        required_modifiers_ok = all(
            modifiers.get(key, "").lower() == value for key, value in required_modifiers.items()
        )

        unexpected_tokens: List[str] = []
        if advanced_checks:
            allowed_base = set()
            allowed_exact = set()
            for token in allowed_mechanisms:
                base, qualifier = self._strip_spf_qualifier(token)
                if qualifier in _SPF_QUALIFIERS:
                    allowed_exact.add(f"{qualifier}{base}")
                else:
                    allowed_base.add(base)
            allowed_base |= set(required_base)
            allowed_exact |= set(required_exact)
            allowed_base |= set(required_includes)
            allowed_base |= set(allowed_includes)
            allowed_base |= {token for token in ip4_tokens if token[4:] in self.additional_spf_ip4}
            allowed_base |= {token for token in ip6_tokens if token[4:] in self.additional_spf_ip6}

            for token in mechanisms:
                if token == policy_required_token:
                    continue
                base, qualifier = self._strip_spf_qualifier(token)
                exact = f"{qualifier}{base}" if qualifier in _SPF_QUALIFIERS else base
                if exact in allowed_exact or base in allowed_base:
                    continue
                unexpected_tokens.append(token)
        else:
            unexpected_tokens = [token for token in include_tokens if token not in allowed_includes]
            unexpected_tokens.extend(
                token for token in ip4_tokens if token[4:] not in self.additional_spf_ip4
            )
            unexpected_tokens.extend(
                token for token in ip6_tokens if token[4:] not in self.additional_spf_ip6
            )

        if (
            has_required_includes
            and policy_ok
            and required_mechanisms_ok
            and required_modifiers_ok
            and not unexpected_tokens
        ):
            return RecordCheck("SPF", "PASS", "SPF record valid", {"record": record})

        if has_required_includes and policy_ok and required_mechanisms_ok and required_modifiers_ok:
            return RecordCheck(
                "SPF",
                "WARN",
                "SPF contains required includes but has extra mechanisms",
                {"record": record, "extras": sorted(set(unexpected_tokens))},
            )

        return RecordCheck(
            "SPF",
            "FAIL",
            "SPF record does not meet requirements",
            {"expected": expected, "found": spf_records},
        )

    def check_dkim(self) -> RecordCheck:
        """Validate DKIM selectors for the configured provider.

        Returns:
            RecordCheck: Result of the DKIM validation.

        Raises:
            ValueError: If the provider does not define DKIM requirements.
        """
        if not self.provider.dkim:
            raise ValueError("DKIM configuration not available for provider")

        missing: List[str] = []
        wrong_target: Dict[str, str] = {}
        selectors_map: Dict[str, str] = {}
        expected_selectors: List[str] = []
        found_selectors: List[str] = []
        if self.provider.dkim.record_type == "cname":
            template = self.provider.dkim.target_template
            for selector in self.provider.dkim.selectors:
                name = f"{selector}._domainkey.{self.domain}"
                expected_target = template.format(selector=selector)
                expected_target = self._normalize_host(expected_target)
                selectors_map[name] = expected_target
                expected_selectors.append(name)

                try:
                    target = self.resolver.get_cname(name)
                except DnsLookupError as err:
                    return RecordCheck("DKIM", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
                if target is None:
                    missing.append(name)
                    continue
                if target.lower() != expected_target.lower():
                    wrong_target[name] = target
                    found_selectors.append(name)
                    continue
                found_selectors.append(name)
        else:
            expected_values = {
                selector: value for selector, value in self.provider.dkim.txt_values.items()
            }
            for selector in self.provider.dkim.selectors:
                name = f"{selector}._domainkey.{self.domain}"
                expected_selectors.append(name)
                expected_value = expected_values.get(selector)
                selectors_map[name] = expected_value or "present"
                try:
                    txt_records = self.resolver.get_txt(name)
                except DnsLookupError as err:
                    return RecordCheck("DKIM", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
                if not txt_records:
                    missing.append(name)
                    continue
                found_selectors.append(name)
                if expected_value:
                    normalized_expected = " ".join(expected_value.split()).lower()
                    normalized_found = [" ".join(record.split()).lower() for record in txt_records]
                    if normalized_expected not in normalized_found:
                        wrong_target[name] = txt_records[0]
                        continue
                    selectors_map[name] = expected_value
                else:
                    selectors_map[name] = "present"

        if missing or wrong_target:
            status = "FAIL" if self.strict or missing else "WARN"
            return RecordCheck(
                "DKIM",
                status,
                "DKIM selectors not fully aligned",
                {
                    "missing": missing,
                    "mismatched": wrong_target,
                    "expected_selectors": expected_selectors,
                    "found_selectors": found_selectors,
                    "expected_targets": selectors_map,
                },
            )

        return RecordCheck(
            "DKIM",
            "PASS",
            "All DKIM selectors configured",
            {"selectors": selectors_map},
        )

    def _evaluate_cname_records(
        self, records: Dict[str, str]
    ) -> tuple[List[str], Dict[str, str], Dict[str, str], Dict[str, str]]:
        """Evaluate CNAME records and return missing/mismatched details.

        Args:
            records (Dict[str, str]): Mapping of name -> expected target.

        Returns:
            tuple[List[str], Dict[str, str], Dict[str, str], Dict[str, str]]: Missing names,
                mismatched values, expected targets, and found targets.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: List[str] = []
        mismatched: Dict[str, str] = {}
        expected_targets: Dict[str, str] = {}
        found_targets: Dict[str, str] = {}

        for name, target in records.items():
            lookup_name = self._normalize_record_name(name)
            expected_target = self._normalize_host(target)
            expected_targets[lookup_name] = expected_target
            found_target = self.resolver.get_cname(lookup_name)
            if found_target is None:
                missing.append(lookup_name)
                continue
            found_targets[lookup_name] = found_target
            if self._normalize_host(found_target) != expected_target:
                mismatched[lookup_name] = found_target

        return missing, mismatched, expected_targets, found_targets

    def check_cname(self) -> RecordCheck:
        """Validate CNAME records for the configured provider.

        Returns:
            RecordCheck: Result of the CNAME validation.

        Raises:
            ValueError: If the provider does not define CNAME requirements.
        """
        if not self.provider.cname:
            raise ValueError("CNAME configuration not available for provider")

        try:
            missing, mismatched, expected_targets, found_targets = self._evaluate_cname_records(
                self.provider.cname.records
            )
        except DnsLookupError as err:
            return RecordCheck("CNAME", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        if missing or mismatched:
            return RecordCheck(
                "CNAME",
                "FAIL",
                "CNAME records do not match required configuration",
                {
                    "missing": missing,
                    "mismatched": mismatched,
                    "expected": expected_targets,
                    "found": found_targets,
                },
            )

        return RecordCheck(
            "CNAME",
            "PASS",
            "Required CNAME records present",
            {"records": expected_targets},
        )

    def check_cname_optional(self) -> RecordCheck:
        """Validate optional CNAME records for the configured provider.

        Returns:
            RecordCheck: Result of the optional CNAME validation.

        Raises:
            ValueError: If the provider does not define CNAME requirements.
        """
        if not self.provider.cname:
            raise ValueError("CNAME configuration not available for provider")

        records_optional = self.provider.cname.records_optional
        if not records_optional:
            return RecordCheck(
                "CNAME",
                "PASS",
                "No optional CNAME records required",
                {},
                optional=True,
            )

        try:
            missing, mismatched, expected_targets, found_targets = self._evaluate_cname_records(
                records_optional
            )
        except DnsLookupError as err:
            return RecordCheck(
                "CNAME",
                "UNKNOWN",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        if missing or mismatched:
            status = "FAIL" if mismatched else "WARN"
            message = (
                "CNAME optional records mismatched"
                if mismatched
                else "CNAME optional records missing"
            )
            return RecordCheck(
                "CNAME",
                status,
                message,
                {
                    "missing": missing,
                    "mismatched": mismatched,
                    "expected": expected_targets,
                    "found": found_targets,
                },
                optional=True,
            )

        return RecordCheck(
            "CNAME",
            "PASS",
            "CNAME optional records present",
            {"records": expected_targets},
            optional=True,
        )

    def _evaluate_caa_records(
        self, records: Dict[str, List["CAARecord"]], *, strict: bool
    ) -> tuple[
        Dict[str, List[Dict[str, object]]],
        Dict[str, List[Dict[str, object]]],
        Dict[str, List[Dict[str, object]]],
        Dict[str, List[Dict[str, object]]],
    ]:
        """Evaluate CAA records and return missing/extra details.

        Args:
            records (Dict[str, List[CAARecord]]): Expected CAA records.
            strict (bool): Whether to require exact matches.

        Returns:
            tuple[Dict[str, List[Dict[str, object]]], ...]: Missing, extra, expected,
                and found entries keyed by name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[Dict[str, object]]] = {}
        extra: Dict[str, List[Dict[str, object]]] = {}
        expected: Dict[str, List[Dict[str, object]]] = {}
        found: Dict[str, List[Dict[str, object]]] = {}

        for name, entries in records.items():
            lookup_name = self._normalize_record_name(name)
            expected_entries = [
                {
                    "flags": int(entry.flags),
                    "tag": str(entry.tag),
                    "value": str(entry.value),
                }
                for entry in entries
            ]
            expected[lookup_name] = expected_entries

            found_entries = self.resolver.get_caa(lookup_name)
            found_entries_dicts = [
                {"flags": int(flags), "tag": str(tag), "value": str(value)}
                for flags, tag, value in found_entries
            ]
            found[lookup_name] = found_entries_dicts

            expected_norm = {
                self._normalize_caa_entry(entry["flags"], entry["tag"], entry["value"]): entry
                for entry in expected_entries
            }
            found_norm = {
                self._normalize_caa_entry(entry["flags"], entry["tag"], entry["value"]): entry
                for entry in found_entries_dicts
            }

            missing_entries = [
                entry for key, entry in expected_norm.items() if key not in found_norm
            ]
            if missing_entries:
                missing[lookup_name] = missing_entries

            if strict:
                extra_entries = [
                    entry for key, entry in found_norm.items() if key not in expected_norm
                ]
                if extra_entries:
                    extra[lookup_name] = extra_entries

        return missing, extra, expected, found

    def check_caa(self) -> RecordCheck:
        """Validate CAA records for the configured provider.

        Returns:
            RecordCheck: Result of the CAA validation.

        Raises:
            ValueError: If the provider does not define CAA requirements.
        """
        if not self.provider.caa:
            raise ValueError("CAA configuration not available for provider")

        try:
            missing, extra, expected, found = self._evaluate_caa_records(
                self.provider.caa.records, strict=self.strict
            )
        except DnsLookupError as err:
            return RecordCheck("CAA", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        if self.strict and (missing or extra):
            details: Dict[str, object] = {"expected": expected, "found": found}
            if missing:
                details["missing"] = missing
            if extra:
                details["extra"] = extra
            return RecordCheck(
                "CAA",
                "FAIL",
                "CAA records do not exactly match required configuration",
                details,
            )

        if missing:
            return RecordCheck(
                "CAA",
                "FAIL",
                "Missing required CAA records",
                {"missing": missing, "expected": expected, "found": found},
            )

        return RecordCheck(
            "CAA",
            "PASS",
            "Required CAA records present",
            {"records": expected},
        )

    def check_caa_optional(self) -> RecordCheck:
        """Validate optional CAA records for the configured provider.

        Returns:
            RecordCheck: Result of the optional CAA validation.

        Raises:
            ValueError: If the provider does not define CAA requirements.
        """
        if not self.provider.caa:
            raise ValueError("CAA configuration not available for provider")

        records_optional = self.provider.caa.records_optional
        if not records_optional:
            return RecordCheck(
                "CAA",
                "PASS",
                "No optional CAA records required",
                {},
                optional=True,
            )

        try:
            missing, _extra, expected, found = self._evaluate_caa_records(
                records_optional, strict=False
            )
        except DnsLookupError as err:
            return RecordCheck(
                "CAA",
                "UNKNOWN",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        if missing:
            return RecordCheck(
                "CAA",
                "WARN",
                "CAA optional records missing",
                {"missing": missing, "expected": expected, "found": found},
                optional=True,
            )

        return RecordCheck(
            "CAA",
            "PASS",
            "CAA optional records present",
            {"records": expected},
            optional=True,
        )

    def check_srv(self) -> RecordCheck:
        """Validate SRV records for the configured provider.

        Returns:
            RecordCheck: Result of the SRV validation.

        Raises:
            ValueError: If the provider does not define SRV requirements.
        """
        if not self.provider.srv:
            raise ValueError("SRV configuration not available for provider")

        try:
            missing, mismatched, extra, expected, found = self._evaluate_srv_records(
                self.provider.srv.records
            )
        except DnsLookupError as err:
            return RecordCheck("SRV", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or mismatched or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if mismatched:
                    details["mismatched"] = mismatched
                if extra:
                    details["extra"] = extra
                return RecordCheck(
                    "SRV",
                    "FAIL",
                    "SRV records do not exactly match required configuration",
                    details,
                )
            return RecordCheck(
                "SRV",
                "PASS",
                "SRV records match required configuration",
                {"records": expected},
            )

        if missing:
            return RecordCheck(
                "SRV",
                "FAIL",
                "Missing required SRV records",
                {"missing": missing, "found": found, "expected": expected},
            )
        if mismatched:
            details = {"mismatched": mismatched, "found": found, "expected": expected}
            if extra:
                details["extra"] = extra
            return RecordCheck(
                "SRV",
                "WARN",
                "SRV priorities or weights differ from expected",
                details,
            )
        if extra:
            return RecordCheck(
                "SRV",
                "WARN",
                "Additional SRV records present; required records found",
                {"extra": extra, "found": found},
            )

        return RecordCheck(
            "SRV",
            "PASS",
            "Required SRV records present",
            {"records": expected},
        )

    def _evaluate_srv_records(self, records: Dict[str, List["SRVRecord"]]) -> tuple[
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[Dict[str, tuple[int, int, int, str]]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
    ]:
        """Evaluate SRV records and return missing/extra details.

        Args:
            records (Dict[str, List[SRVRecord]]): Expected SRV records.

        Returns:
            tuple[Dict[str, List[tuple[int, int, int, str]]], ...]: Missing, mismatched, extra,
                expected, and found entries keyed by name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[tuple[int, int, int, str]]] = {}
        mismatched: Dict[str, List[Dict[str, tuple[int, int, int, str]]]] = {}
        extra: Dict[str, List[tuple[int, int, int, str]]] = {}
        expected: Dict[str, List[tuple[int, int, int, str]]] = {}
        found: Dict[str, List[tuple[int, int, int, str]]] = {}

        for name, entries in records.items():
            lookup_name = self._normalize_record_name(name)
            expected_entries = [
                (
                    int(entry.priority),
                    int(entry.weight),
                    int(entry.port),
                    self._normalize_host(entry.target),
                )
                for entry in entries
            ]
            expected[lookup_name] = expected_entries
            found_entries = self.resolver.get_srv(lookup_name)
            normalized_found = [
                (int(priority), int(weight), int(port), self._normalize_host(target))
                for priority, weight, port, target in found_entries
            ]
            normalized_found = sorted(
                normalized_found, key=lambda entry: (entry[3], entry[2], entry[0], entry[1])
            )
            found[lookup_name] = normalized_found
            remaining_found = list(normalized_found)
            missing_entries: List[tuple[int, int, int, str]] = []
            mismatched_entries: List[Dict[str, tuple[int, int, int, str]]] = []

            for entry in expected_entries:
                if entry in remaining_found:
                    remaining_found.remove(entry)
                    continue
                expected_target, expected_port = entry[3], entry[2]
                match_index = next(
                    (
                        index
                        for index, found_entry in enumerate(remaining_found)
                        if found_entry[3] == expected_target and found_entry[2] == expected_port
                    ),
                    None,
                )
                if match_index is None:
                    missing_entries.append(entry)
                    continue
                found_entry = remaining_found.pop(match_index)
                mismatched_entries.append({"expected": entry, "found": found_entry})

            if missing_entries:
                missing[lookup_name] = missing_entries
            if mismatched_entries:
                mismatched[lookup_name] = mismatched_entries
            if remaining_found:
                extra[lookup_name] = sorted(remaining_found)

        return missing, mismatched, extra, expected, found

    def check_srv_optional(self) -> RecordCheck:
        """Validate optional SRV records for the configured provider.

        Returns:
            RecordCheck: Result of the optional SRV validation.

        Raises:
            ValueError: If the provider does not define SRV requirements.
        """
        if not self.provider.srv:
            raise ValueError("SRV configuration not available for provider")

        records_optional = self.provider.srv.records_optional
        if not records_optional:
            return RecordCheck(
                "SRV",
                "PASS",
                "No optional SRV records required",
                {},
                optional=True,
            )

        try:
            missing, mismatched, extra, expected, found = self._evaluate_srv_records(
                records_optional
            )
        except DnsLookupError as err:
            return RecordCheck(
                "SRV",
                "UNKNOWN",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(mismatched) or bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck(
                "SRV",
                "FAIL",
                "SRV optional records mismatched",
                {
                    "missing": missing,
                    "mismatched": mismatched,
                    "extra": extra,
                    "found": found,
                    "expected": expected,
                },
                optional=True,
            )
        if missing:
            return RecordCheck(
                "SRV",
                "WARN",
                "SRV optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck(
            "SRV",
            "PASS",
            "SRV optional records present",
            {"records": expected},
            optional=True,
        )

    def check_txt(self) -> RecordCheck:
        """Validate TXT records for the configured provider and overrides.

        Returns:
            RecordCheck: Result of the TXT validation.
        """
        required: Dict[str, List[str]] = {}
        user_required = False
        if self.provider.txt:
            required.update(self.provider.txt.required)
            user_required = self.provider.txt.verification_required
        for name, values in self.additional_txt.items():
            required.setdefault(name, []).extend(values)
        if not self.skip_txt_verification:
            for name, values in self.additional_txt_verification.items():
                required.setdefault(name, []).extend(values)

        verification_warning = (
            user_required
            and not self.additional_txt_verification
            and not self.skip_txt_verification
        )

        if not required:
            if verification_warning:
                return RecordCheck(
                    "TXT",
                    "WARN",
                    "TXT record required for domain verification",
                    {"required": "user-supplied TXT verification value"},
                )
            return RecordCheck("TXT", "PASS", "No TXT records required", {})

        missing_names: List[str] = []
        missing_values: Dict[str, List[str]] = {}
        found_values: Dict[str, List[str]] = {}

        for name, expected_values in required.items():
            lookup_name = self._normalize_txt_name(name)
            try:
                records = self.resolver.get_txt(lookup_name)
            except DnsLookupError as err:
                return RecordCheck("TXT", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
            normalized_found = [" ".join(record.split()).lower() for record in records]
            found_values[name] = records
            if not records:
                missing_names.append(name)
                missing_values[name] = list(expected_values)
                continue

            for expected in expected_values:
                normalized_expected = " ".join(str(expected).split()).lower()
                if normalized_expected not in normalized_found:
                    missing_values.setdefault(name, []).append(expected)

        if missing_names or missing_values:
            details: Dict[str, object] = {"missing": missing_values}
            if missing_names:
                details["missing_names"] = sorted(missing_names)
            if verification_warning:
                details["verification_required"] = "user-supplied TXT verification value"
            return RecordCheck("TXT", "FAIL", "TXT records missing required values", details)

        if verification_warning:
            return RecordCheck(
                "TXT",
                "WARN",
                "TXT record required for domain verification",
                {"required": "user-supplied TXT verification value"},
            )

        return RecordCheck("TXT", "PASS", "TXT records present", {"required": required})

    def _expected_dmarc_value(
        self,
        required_rua: List[str],
        rua_required: bool,
        required_ruf: List[str],
        ruf_required: bool,
    ) -> str:
        """Build the expected DMARC policy string.

        Args:
            required_rua (List[str]): Required rua values.
            rua_required (bool): Whether rua is required.
            required_ruf (List[str]): Required ruf values.
            ruf_required (bool): Whether ruf is required.

        Returns:
            str: Expected DMARC record string.
        """
        policy = self.dmarc_policy
        parts = [f"v=DMARC1", f"p={policy}"]
        if rua_required:
            rua_value = ",".join(required_rua) if required_rua else "<required>"
            parts.append(f"rua={rua_value}")
        if ruf_required:
            ruf_value = ",".join(required_ruf) if required_ruf else "<required>"
            parts.append(f"ruf={ruf_value}")
        if self.dmarc_required_tags:
            for key in sorted(self.dmarc_required_tags.keys()):
                parts.append(f"{key}={self.dmarc_required_tags[key]}")
        return ";".join(parts)

    @staticmethod
    def _parse_dmarc_tokens(record: str) -> Dict[str, str]:
        """Parse a DMARC record into a tag map.

        Args:
            record (str): Raw DMARC record string.

        Returns:
            Dict[str, str]: Mapping of tag to value.
        """
        parts = [part for part in record.replace(" ", "").split(";") if "=" in part]
        return {part.split("=", 1)[0].lower(): part.split("=", 1)[1] for part in parts}

    @staticmethod
    def _parse_mailto_entries(raw_value: str) -> List[str]:
        """Parse a DMARC mailto value list.

        Args:
            raw_value (str): Comma-separated mailto entries.

        Returns:
            List[str]: Normalized mailto entries.
        """
        return [entry.strip().lower() for entry in raw_value.split(",") if entry.strip()]

    @staticmethod
    def _matches_dmarc_uri(required: str, found: str) -> bool:
        """Check if a found mailto entry satisfies a required entry.

        Args:
            required (str): Required mailto URI.
            found (str): Found mailto URI.

        Returns:
            bool: True if the found entry satisfies the requirement.
        """
        if required == found:
            return True
        if not required.startswith("mailto:") or not found.startswith("mailto:"):
            return False
        if "!" in required or "?" in required:
            return False
        if not found.startswith(required):
            return False
        suffix = found[len(required) :]
        return not suffix or suffix[0] in {"!", "?"}

    def _required_dmarc_uris_present(self, required: List[str], found: List[str]) -> bool:
        """Check that all required DMARC URIs appear in the found list.

        Args:
            required (List[str]): Required mailto URIs.
            found (List[str]): Found mailto URIs.

        Returns:
            bool: True if every required entry is present.
        """
        return all(
            any(self._matches_dmarc_uri(required_value, entry) for entry in found)
            for required_value in required
        )

    def _strict_dmarc_uris_match(self, required: List[str], found: List[str]) -> bool:
        """Check that required and found DMARC URIs match exactly.

        Args:
            required (List[str]): Required mailto URIs.
            found (List[str]): Found mailto URIs.

        Returns:
            bool: True if both sets match under DMARC matching rules.
        """
        for required_value in required:
            if not any(self._matches_dmarc_uri(required_value, entry) for entry in found):
                return False
        for entry in found:
            if not any(
                self._matches_dmarc_uri(required_value, entry) for required_value in required
            ):
                return False
        return True

    def check_dmarc(self) -> RecordCheck:
        """Validate DMARC records for the configured provider.

        Returns:
            RecordCheck: Result of the DMARC validation.

        Raises:
            ValueError: If the provider does not define DMARC requirements.
        """
        if not self.provider.dmarc:
            raise ValueError("DMARC configuration not available for provider")

        name = f"_dmarc.{self.domain}"
        try:
            txt_records = self.resolver.get_txt(name)
        except DnsLookupError as err:
            return RecordCheck("DMARC", "UNKNOWN", "DNS lookup failed", {"error": str(err)})

        required_rua = self._effective_required_rua()
        rua_required = self._rua_required(required_rua)
        required_ruf = self._effective_required_ruf()
        ruf_required = self._ruf_required(required_ruf)
        expected = self._expected_dmarc_value(
            required_rua, rua_required, required_ruf, ruf_required
        )
        if not txt_records:
            return RecordCheck(
                "DMARC",
                "FAIL",
                "No DMARC record found",
                {"expected": expected},
            )
        required_tags = {key: value.lower() for key, value in self.dmarc_required_tags.items()}

        for record in txt_records:
            if self.strict:
                tokens = self._parse_dmarc_tokens(record)
                if tokens.get("v", "").upper() != "DMARC1":
                    continue
                if tokens.get("p", "").lower() != self.dmarc_policy:
                    continue
                rua_entries = self._parse_mailto_entries(tokens.get("rua", ""))
                ruf_entries = self._parse_mailto_entries(tokens.get("ruf", ""))
                if rua_required:
                    if not rua_entries:
                        continue
                    if required_rua and not self._strict_dmarc_uris_match(
                        required_rua, rua_entries
                    ):
                        continue
                if ruf_required:
                    if not ruf_entries:
                        continue
                    if required_ruf and not self._strict_dmarc_uris_match(
                        required_ruf, ruf_entries
                    ):
                        continue
                missing_tags = {
                    key: value
                    for key, value in required_tags.items()
                    if tokens.get(key, "").lower() != value
                }
                if missing_tags:
                    continue
                allowed_tags = {"v", "p"}
                if rua_required:
                    allowed_tags.add("rua")
                if ruf_required:
                    allowed_tags.add("ruf")
                allowed_tags.update(required_tags.keys())
                if set(tokens.keys()) != allowed_tags:
                    continue
                return RecordCheck(
                    "DMARC",
                    "PASS",
                    "DMARC record matches strict configuration",
                    {"record": record},
                )
                continue

            tokens = self._parse_dmarc_tokens(record)
            policy = tokens.get("p", "").lower()
            rua_entries = self._parse_mailto_entries(tokens.get("rua", ""))
            ruf_entries = self._parse_mailto_entries(tokens.get("ruf", ""))

            if tokens.get("v", "").upper() != "DMARC1":
                continue
            if policy != self.dmarc_policy:
                continue
            if rua_required:
                if not rua_entries:
                    continue
                if required_rua and not self._required_dmarc_uris_present(
                    required_rua, rua_entries
                ):
                    continue
            if ruf_required:
                if not ruf_entries:
                    continue
                if required_ruf and not self._required_dmarc_uris_present(
                    required_ruf, ruf_entries
                ):
                    continue

            missing_tags = {
                key: value
                for key, value in required_tags.items()
                if tokens.get(key, "").lower() != value
            }
            if missing_tags:
                continue

            status = "PASS"
            message = (
                "DMARC policy present"
                if not rua_entries and not ruf_entries
                else "DMARC policy and reporting tags present"
            )
            details = {"record": record}
            return RecordCheck("DMARC", status, message, details)

        return RecordCheck(
            "DMARC",
            "FAIL",
            "DMARC record does not meet guidance",
            {"expected": expected, "found": txt_records},
        )
