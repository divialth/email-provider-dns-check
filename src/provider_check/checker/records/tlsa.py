"""TLSA record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class TlsaChecksMixin:
    """Validate TLSA records."""

    def _evaluate_tlsa_records(
        self,
        records: Dict[str, List["TLSARecord"]],
    ) -> tuple[
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
        Dict[str, List[tuple[int, int, int, str]]],
    ]:
        """Evaluate TLSA records and return missing/extra details.

        Args:
            records (Dict[str, List[TLSARecord]]): Expected TLSA records.

        Returns:
            tuple[Dict[str, List[tuple[int, int, int, str]]], ...]: Missing, extra,
                expected, and found entries keyed by name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        missing: Dict[str, List[tuple[int, int, int, str]]] = {}
        extra: Dict[str, List[tuple[int, int, int, str]]] = {}
        expected: Dict[str, List[tuple[int, int, int, str]]] = {}
        found: Dict[str, List[tuple[int, int, int, str]]] = {}

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

            found_entries = [
                self._normalize_tlsa_entry(usage, selector, matching_type, certificate_association)
                for usage, selector, matching_type, certificate_association in self.resolver.get_tlsa(
                    lookup_name
                )
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

        return missing, extra, expected, found

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
            missing, extra, expected, found = self._evaluate_tlsa_records(
                self.provider.tlsa.required
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("TLSA", "DNS lookup failed", {"error": str(err)})

        if self.strict:
            if missing or extra:
                details: Dict[str, object] = {"expected": expected, "found": found}
                if missing:
                    details["missing"] = missing
                if extra:
                    details["extra"] = extra
                return RecordCheck.fail(
                    "TLSA",
                    "TLSA records do not exactly match required configuration",
                    details,
                )
            return RecordCheck.pass_(
                "TLSA",
                "TLSA records match required configuration",
                {"expected": expected},
            )

        if missing:
            return RecordCheck.fail(
                "TLSA",
                "Missing required TLSA records",
                {"missing": missing, "expected": expected, "found": found},
            )

        if extra:
            return RecordCheck.warn(
                "TLSA",
                "Additional TLSA records present; required records found",
                {"extra": extra, "found": found, "expected": expected},
            )

        return RecordCheck.pass_(
            "TLSA",
            "Required TLSA records present",
            {"expected": expected},
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
            missing, extra, expected, found = self._evaluate_tlsa_records(optional_records)
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
                {"missing": missing, "extra": extra, "found": found, "expected": expected},
                optional=True,
            )
        if missing:
            return RecordCheck.warn(
                "TLSA",
                "TLSA optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck.pass_(
            "TLSA",
            "TLSA optional records present",
            {"expected": expected},
            optional=True,
        )
