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
