"""Address record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class AddressChecksMixin:
    """Validate A and AAAA records."""

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
                self.provider.a.required, self.resolver.get_a
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("A", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck.fail(
                    "A",
                    "A records do not exactly match required configuration",
                    details,
                )
            return RecordCheck.pass_(
                "A",
                "A records match required configuration",
                {"expected": expected},
            )

        if missing:
            return RecordCheck.fail(
                "A",
                "Missing required A records",
                {"missing": missing, "expected": expected, "found": found},
            )
        if extra:
            return RecordCheck.warn(
                "A",
                "Additional A records present; required values found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck.pass_(
            "A",
            "Required A records present",
            {"expected": expected},
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

        optional_records = self.provider.a.optional
        if not optional_records:
            return RecordCheck.pass_(
                "A",
                "No optional A records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                optional_records, self.resolver.get_a
            )
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "A",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck.fail(
                "A",
                "A optional records mismatched",
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck.warn(
                "A",
                "A optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck.pass_(
            "A",
            "A optional records present",
            {"expected": expected},
            optional=True,
        )

    def _evaluate_address_match_rules(
        self,
        rules: Dict[str, "ValuesMatchRule"],
        lookup,
    ) -> tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]:
        """Evaluate negative A/AAAA match rules.

        Args:
            rules (Dict[str, ValuesMatchRule]): Match rules keyed by record name.
            lookup (callable): DNS lookup function for the record type.

        Returns:
            tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]: Matched,
                expected, and found values keyed by record name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        matched: Dict[str, List[str]] = {}
        expected: Dict[str, List[str]] = {}
        found: Dict[str, List[str]] = {}
        for name, rule in rules.items():
            lookup_name = self._normalize_record_name(name)
            found_values = [self._normalize_address_value(value) for value in lookup(lookup_name)]
            found[lookup_name] = found_values
            expected_values = [self._normalize_address_value(value) for value in rule.values]
            expected[lookup_name] = expected_values
            if rule.match == "any":
                if found_values:
                    matched[lookup_name] = sorted(set(found_values))
                continue
            overlap = sorted(set(expected_values) & set(found_values))
            if overlap:
                matched[lookup_name] = overlap
        return matched, expected, found

    def _check_address_negative(
        self,
        record_type: str,
        rules: Dict[str, "ValuesMatchRule"],
        lookup,
        *,
        scope: str,
    ) -> RecordCheck:
        """Run deprecated/forbidden checks for A/AAAA records.

        Args:
            record_type (str): Record type label ("A" or "AAAA").
            rules (Dict[str, ValuesMatchRule]): Match rules keyed by record name.
            lookup (callable): DNS lookup function.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific address match result.
        """
        if not rules:
            return RecordCheck.pass_(
                record_type,
                f"No {scope} {record_type} records configured",
                {},
                scope=scope,
            )
        try:
            matched, expected, found = self._evaluate_address_match_rules(rules, lookup)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                record_type,
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        if matched:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                record_type,
                f"{scope.capitalize()} {record_type} records are present",
                {"matched": matched, "expected": expected, "found": found},
                scope=scope,
            )
        return RecordCheck.pass_(
            record_type,
            f"No {scope} {record_type} records present",
            {"expected": expected},
            scope=scope,
        )

    def check_a_deprecated(self) -> RecordCheck:
        """Validate deprecated A records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated A record validation.

        Raises:
            ValueError: If the provider does not define A requirements.
        """
        if not self.provider.a:
            raise ValueError("A configuration not available for provider")
        return self._check_address_negative(
            "A", self.provider.a.deprecated, self.resolver.get_a, scope="deprecated"
        )

    def check_a_forbidden(self) -> RecordCheck:
        """Validate forbidden A records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden A record validation.

        Raises:
            ValueError: If the provider does not define A requirements.
        """
        if not self.provider.a:
            raise ValueError("A configuration not available for provider")
        return self._check_address_negative(
            "A", self.provider.a.forbidden, self.resolver.get_a, scope="forbidden"
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
                self.provider.aaaa.required, self.resolver.get_aaaa
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("AAAA", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck.fail(
                    "AAAA",
                    "AAAA records do not exactly match required configuration",
                    details,
                )
            return RecordCheck.pass_(
                "AAAA",
                "AAAA records match required configuration",
                {"expected": expected},
            )

        if missing:
            return RecordCheck.fail(
                "AAAA",
                "Missing required AAAA records",
                {"missing": missing, "expected": expected, "found": found},
            )
        if extra:
            return RecordCheck.warn(
                "AAAA",
                "Additional AAAA records present; required values found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck.pass_(
            "AAAA",
            "Required AAAA records present",
            {"expected": expected},
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

        optional_records = self.provider.aaaa.optional
        if not optional_records:
            return RecordCheck.pass_(
                "AAAA",
                "No optional AAAA records required",
                {},
                optional=True,
            )

        try:
            missing, extra, expected, found = self._evaluate_address_records(
                optional_records, self.resolver.get_aaaa
            )
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "AAAA",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck.fail(
                "AAAA",
                "AAAA optional records mismatched",
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck.warn(
                "AAAA",
                "AAAA optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck.pass_(
            "AAAA",
            "AAAA optional records present",
            {"expected": expected},
            optional=True,
        )

    def check_aaaa_deprecated(self) -> RecordCheck:
        """Validate deprecated AAAA records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated AAAA record validation.

        Raises:
            ValueError: If the provider does not define AAAA requirements.
        """
        if not self.provider.aaaa:
            raise ValueError("AAAA configuration not available for provider")
        return self._check_address_negative(
            "AAAA",
            self.provider.aaaa.deprecated,
            self.resolver.get_aaaa,
            scope="deprecated",
        )

    def check_aaaa_forbidden(self) -> RecordCheck:
        """Validate forbidden AAAA records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden AAAA record validation.

        Raises:
            ValueError: If the provider does not define AAAA requirements.
        """
        if not self.provider.aaaa:
            raise ValueError("AAAA configuration not available for provider")
        return self._check_address_negative(
            "AAAA",
            self.provider.aaaa.forbidden,
            self.resolver.get_aaaa,
            scope="forbidden",
        )
