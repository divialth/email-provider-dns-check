"""Core DNS validation logic."""

from __future__ import annotations

import dataclasses
import logging
from typing import Dict, Iterable, List, Optional

from .dns_resolver import DnsLookupError, DnsResolver
from .provider_config import ProviderConfig

LOGGER = logging.getLogger(__name__)
_SPF_QUALIFIERS = {"-", "~", "?"}


@dataclasses.dataclass
class RecordCheck:
    record_type: str
    status: str  # PASS | WARN | FAIL
    message: str
    details: Dict[str, object]


class DNSChecker:
    """Validate provider-specific DNS records for a domain."""

    def __init__(
        self,
        domain: str,
        provider: ProviderConfig,
        resolver: Optional[DnsResolver] = None,
        *,
        strict: bool = False,
        dmarc_email: Optional[str] = None,
        dmarc_policy: Optional[str] = None,
        spf_policy: str = "hardfail",
        additional_spf_includes: Optional[Iterable[str]] = None,
        additional_spf_ip4: Optional[Iterable[str]] = None,
        additional_spf_ip6: Optional[Iterable[str]] = None,
        additional_txt: Optional[Dict[str, Iterable[str]]] = None,
        additional_txt_verification: Optional[Dict[str, Iterable[str]]] = None,
        skip_txt_verification: bool = False,
    ) -> None:
        self.domain = domain.lower().strip()
        self.provider = provider
        self.resolver = resolver or DnsResolver()
        self.strict = strict
        self._dmarc_email_override = dmarc_email is not None

        dmarc_default_policy = "reject"
        dmarc_default_rua_localpart = "postmaster"
        if provider.dmarc:
            dmarc_default_policy = provider.dmarc.default_policy
            dmarc_default_rua_localpart = provider.dmarc.default_rua_localpart

        self.dmarc_policy = (dmarc_policy or dmarc_default_policy).lower()
        self.dmarc_email = dmarc_email or f"{dmarc_default_rua_localpart}@{self.domain}"
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
        results: List[RecordCheck] = []
        if self.provider.mx:
            results.append(self.check_mx())
        if self.provider.spf:
            results.append(self.check_spf())
        if self.provider.dkim:
            results.append(self.check_dkim())
        if self.provider.txt or self.additional_txt or self.additional_txt_verification:
            results.append(self.check_txt())
        if self.provider.dmarc:
            results.append(self.check_dmarc())
        return results

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.rstrip(".").lower() + "."

    @staticmethod
    def _strip_spf_qualifier(token: str) -> tuple[str, str]:
        if token and token[0] in "+-~?":
            return token[1:], token[0]
        return token, ""

    def _normalize_txt_name(self, name: str) -> str:
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

    def check_mx(self) -> RecordCheck:
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

    def _build_expected_spf(self) -> str:
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

    def check_txt(self) -> RecordCheck:
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

    def _expected_dmarc_value(self) -> str:
        policy = self.dmarc_policy
        if self.provider.dmarc and self.provider.dmarc.required_rua:
            rua_value = ",".join(self.provider.dmarc.required_rua)
        else:
            rua_value = f"mailto:{self.dmarc_email}"
        parts = [f"v=DMARC1", f"p={policy}", f"rua={rua_value}"]
        if self.provider.dmarc and self.provider.dmarc.required_tags:
            for key in sorted(self.provider.dmarc.required_tags.keys()):
                parts.append(f"{key}={self.provider.dmarc.required_tags[key]}")
        return ";".join(parts)

    def check_dmarc(self) -> RecordCheck:
        if not self.provider.dmarc:
            raise ValueError("DMARC configuration not available for provider")

        name = f"_dmarc.{self.domain}"
        try:
            txt_records = self.resolver.get_txt(name)
        except DnsLookupError as err:
            return RecordCheck("DMARC", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
        if not txt_records:
            return RecordCheck(
                "DMARC",
                "FAIL",
                "No DMARC record found",
                {"expected": self._expected_dmarc_value()},
            )

        expected = self._expected_dmarc_value()
        required_rua = [addr.lower() for addr in self.provider.dmarc.required_rua]
        required_tags = {
            key.lower(): value.lower() for key, value in self.provider.dmarc.required_tags.items()
        }

        for record in txt_records:
            normalized = "".join(record.split())
            if self.strict:
                if normalized.lower() == expected.lower():
                    return RecordCheck(
                        "DMARC",
                        "PASS",
                        "DMARC record matches strict configuration",
                        {"record": record},
                    )
                continue

            parts = [part for part in record.replace(" ", "").split(";") if "=" in part]
            tokens = {part.split("=", 1)[0].lower(): part.split("=", 1)[1] for part in parts}
            policy = tokens.get("p", "").lower()
            rua_raw = tokens.get("rua", "")
            rua_entries = [entry.strip().lower() for entry in rua_raw.split(",") if entry.strip()]

            if tokens.get("v", "").upper() != "DMARC1":
                continue
            if policy != self.dmarc_policy:
                continue
            if not rua_entries:
                continue
            if required_rua and not all(addr in rua_entries for addr in required_rua):
                continue

            missing_tags = {
                key: value
                for key, value in required_tags.items()
                if tokens.get(key, "").lower() != value
            }
            if missing_tags:
                continue

            status = "PASS"
            message = "DMARC policy and rua present"
            details = {"record": record}
            expected_rua = f"mailto:{self.dmarc_email}".lower()
            warn_on_rua = self._dmarc_email_override or not required_rua
            if warn_on_rua and expected_rua not in rua_entries:
                status = "WARN"
                message = "DMARC rua differs from expected"
                details["expected_rua"] = expected_rua
            return RecordCheck("DMARC", status, message, details)

        return RecordCheck(
            "DMARC",
            "FAIL",
            "DMARC record does not meet guidance",
            {"expected": expected, "found": txt_records},
        )
