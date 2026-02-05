"""SPF record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from ..utils import SPF_QUALIFIERS, strip_spf_qualifier
from .models import RecordCheck


class SpfChecksMixin:
    """Validate SPF records."""

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
        if self.strict and spf_config.required.record:
            return spf_config.required.record

        tokens: List[str] = ["v=spf1"]
        tokens.extend(f"include:{value}" for value in spf_config.required.includes)
        tokens.extend(spf_config.required.mechanisms)
        if not self.strict:
            tokens.extend(f"include:{value}" for value in self.additional_spf_includes)
            tokens.extend(f"ip4:{value}" for value in self.additional_spf_ip4)
            tokens.extend(f"ip6:{value}" for value in self.additional_spf_ip6)
        if spf_config.required.modifiers:
            for key in sorted(spf_config.required.modifiers.keys()):
                tokens.append(f"{key}={spf_config.required.modifiers[key]}")
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
            return RecordCheck.unknown("SPF", "DNS lookup failed", {"error": str(err)})
        spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]

        if not spf_records:
            return RecordCheck.fail(
                "SPF",
                "No SPF record found",
                {"expected": self._build_expected_spf()},
            )

        if len(spf_records) > 1:
            return RecordCheck.fail(
                "SPF",
                "Multiple SPF records found",
                {"found": spf_records},
            )

        expected = self._build_expected_spf()
        record = spf_records[0]
        normalized = " ".join(record.split())
        if self.strict:
            if normalized.lower() == expected.lower():
                return RecordCheck.pass_(
                    "SPF",
                    "SPF record matches strict setup",
                    {"record": record},
                )
            return RecordCheck.fail(
                "SPF",
                "SPF record does not match strict configuration",
                {"expected": expected, "found": record},
            )

        required_includes = {f"include:{value.lower()}" for value in spf_config.required.includes}
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
            base, _ = strip_spf_qualifier(token)
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

        required_mechanisms = [value.lower() for value in spf_config.required.mechanisms]
        allowed_mechanisms = [value.lower() for value in spf_config.optional.mechanisms]
        required_modifiers = {
            key.lower(): value.lower() for key, value in spf_config.required.modifiers.items()
        }
        advanced_checks = bool(required_mechanisms or allowed_mechanisms)

        mechanism_bases_present = {strip_spf_qualifier(token)[0] for token in mechanisms}
        mechanism_exact_present = {
            f"{qualifier}{base}"
            for token in mechanisms
            for base, qualifier in [strip_spf_qualifier(token)]
            if qualifier in SPF_QUALIFIERS
        }

        required_base = set()
        required_exact = set()
        for token in required_mechanisms:
            base, qualifier = strip_spf_qualifier(token)
            if qualifier in SPF_QUALIFIERS:
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
                base, qualifier = strip_spf_qualifier(token)
                if qualifier in SPF_QUALIFIERS:
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
                base, qualifier = strip_spf_qualifier(token)
                exact = f"{qualifier}{base}" if qualifier in SPF_QUALIFIERS else base
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
            return RecordCheck.pass_("SPF", "SPF record valid", {"record": record})

        if has_required_includes and policy_ok and required_mechanisms_ok and required_modifiers_ok:
            return RecordCheck.warn(
                "SPF",
                "SPF contains required includes but has extra mechanisms",
                {"record": record, "extras": sorted(set(unexpected_tokens))},
            )

        return RecordCheck.fail(
            "SPF",
            "SPF record does not meet requirements",
            {"expected": expected, "found": spf_records},
        )
