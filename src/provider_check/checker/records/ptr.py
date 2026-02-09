"""PTR record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class PtrChecksMixin:
    """Validate PTR records."""

    def _normalize_ptr_name(self, name: str) -> str:
        """Normalize a PTR lookup name.

        Args:
            name (str): PTR reverse lookup name.

        Returns:
            str: Normalized reverse lookup name without trailing dot.
        """
        trimmed = name.strip()
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if trimmed.endswith("."):
            return trimmed[:-1]
        lowered = trimmed.lower()
        if lowered.endswith(".in-addr.arpa") or lowered.endswith(".ip6.arpa"):
            return trimmed
        return self._normalize_record_name(trimmed)

    def _evaluate_ptr_records(
        self,
        records: Dict[str, List[str]],
    ) -> tuple[
        Dict[str, List[str]],
        Dict[str, List[str]],
        Dict[str, List[str]],
        Dict[str, List[str]],
    ]:
        """Evaluate PTR records and return missing/extra details.

        Args:
            records (Dict[str, List[str]]): Expected PTR records mapping.

        Returns:
            tuple[Dict[str, List[str]], ...]: Missing, extra, expected, and found values keyed by
                reverse DNS name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[str]] = {}
        extra: Dict[str, List[str]] = {}
        expected: Dict[str, List[str]] = {}
        found: Dict[str, List[str]] = {}

        for name, values in records.items():
            lookup_name = self._normalize_ptr_name(name)
            expected_values = [self._normalize_host(value) for value in values]
            expected[lookup_name] = expected_values

            found_values = [
                self._normalize_host(value) for value in self.resolver.get_ptr(lookup_name)
            ]
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

    def check_ptr(self) -> RecordCheck:
        """Validate PTR records for the configured provider.

        Returns:
            RecordCheck: Result of the PTR validation.

        Raises:
            ValueError: If the provider does not define PTR requirements.
        """
        if not self.provider.ptr:
            raise ValueError("PTR configuration not available for provider")

        try:
            missing, extra, expected, found = self._evaluate_ptr_records(self.provider.ptr.required)
        except DnsLookupError as err:
            return RecordCheck.unknown("PTR", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck.fail(
                    "PTR",
                    "PTR records do not exactly match required configuration",
                    details,
                )
            return RecordCheck.pass_(
                "PTR",
                "PTR records match required configuration",
                {"expected": expected},
            )

        if missing:
            return RecordCheck.fail(
                "PTR",
                "Missing required PTR records",
                {"missing": missing, "expected": expected, "found": found},
            )
        if extra:
            return RecordCheck.warn(
                "PTR",
                "Additional PTR records present; required values found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck.pass_(
            "PTR",
            "Required PTR records present",
            {"expected": expected},
        )

    def check_ptr_optional(self) -> RecordCheck:
        """Validate optional PTR records for the configured provider.

        Returns:
            RecordCheck: Result of the optional PTR validation.

        Raises:
            ValueError: If the provider does not define PTR requirements.
        """
        if not self.provider.ptr:
            raise ValueError("PTR configuration not available for provider")

        optional_records = self.provider.ptr.optional
        if not optional_records:
            return RecordCheck.pass_(
                "PTR",
                "No optional PTR records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found = self._evaluate_ptr_records(optional_records)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "PTR",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck.fail(
                "PTR",
                "PTR optional records mismatched",
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck.warn(
                "PTR",
                "PTR optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck.pass_(
            "PTR",
            "PTR optional records present",
            {"expected": expected},
            optional=True,
        )

    def _evaluate_ptr_match_rules(
        self, rules: Dict[str, "ValuesMatchRule"]
    ) -> tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]:
        """Evaluate negative PTR match rules.

        Args:
            rules (Dict[str, ValuesMatchRule]): Match rules keyed by reverse DNS name.

        Returns:
            tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]: Matched,
                expected, and found values keyed by reverse DNS name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        matched: Dict[str, List[str]] = {}
        expected: Dict[str, List[str]] = {}
        found: Dict[str, List[str]] = {}
        for name, rule in rules.items():
            lookup_name = self._normalize_ptr_name(name)
            found_values = [
                self._normalize_host(value) for value in self.resolver.get_ptr(lookup_name)
            ]
            found[lookup_name] = found_values
            expected_values = [self._normalize_host(value) for value in rule.values]
            expected[lookup_name] = expected_values
            if rule.match == "any":
                if found_values:
                    matched[lookup_name] = sorted(set(found_values))
                continue
            overlap = sorted(set(expected_values) & set(found_values))
            if overlap:
                matched[lookup_name] = overlap
        return matched, expected, found

    def _check_ptr_negative(
        self, rules: Dict[str, "ValuesMatchRule"], *, scope: str
    ) -> RecordCheck:
        """Run deprecated/forbidden checks for PTR records.

        Args:
            rules (Dict[str, ValuesMatchRule]): Match rules keyed by reverse DNS name.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific PTR match result.
        """
        if not rules:
            return RecordCheck.pass_(
                "PTR",
                f"No {scope} PTR records configured",
                {},
                scope=scope,
            )
        try:
            matched, expected, found = self._evaluate_ptr_match_rules(rules)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "PTR",
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        if matched:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                "PTR",
                f"{scope.capitalize()} PTR records are present",
                {"matched": matched, "expected": expected, "found": found},
                scope=scope,
            )
        return RecordCheck.pass_(
            "PTR",
            f"No {scope} PTR records present",
            {"expected": expected},
            scope=scope,
        )

    def check_ptr_deprecated(self) -> RecordCheck:
        """Validate deprecated PTR records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated PTR record validation.

        Raises:
            ValueError: If the provider does not define PTR requirements.
        """
        if not self.provider.ptr:
            raise ValueError("PTR configuration not available for provider")
        return self._check_ptr_negative(self.provider.ptr.deprecated, scope="deprecated")

    def check_ptr_forbidden(self) -> RecordCheck:
        """Validate forbidden PTR records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden PTR record validation.

        Raises:
            ValueError: If the provider does not define PTR requirements.
        """
        if not self.provider.ptr:
            raise ValueError("PTR configuration not available for provider")
        return self._check_ptr_negative(self.provider.ptr.forbidden, scope="forbidden")
