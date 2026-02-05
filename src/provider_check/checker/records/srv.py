"""SRV record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from ...status import Status
from .models import RecordCheck


class SrvChecksMixin:
    """Validate SRV records."""

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
            return RecordCheck(
                "SRV", Status.UNKNOWN.value, "DNS lookup failed", {"error": str(err)}
            )

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
                    Status.FAIL.value,
                    "SRV records do not exactly match required configuration",
                    details,
                )
            return RecordCheck(
                "SRV",
                Status.PASS.value,
                "SRV records match required configuration",
                {"records": expected},
            )

        if missing:
            return RecordCheck(
                "SRV",
                Status.FAIL.value,
                "Missing required SRV records",
                {"missing": missing, "found": found, "expected": expected},
            )
        if mismatched:
            details = {"mismatched": mismatched, "found": found, "expected": expected}
            if extra:
                details["extra"] = extra
            return RecordCheck(
                "SRV",
                Status.WARN.value,
                "SRV priorities or weights differ from expected",
                details,
            )
        if extra:
            return RecordCheck(
                "SRV",
                Status.WARN.value,
                "Additional SRV records present; required records found",
                {"extra": extra, "found": found},
            )

        return RecordCheck(
            "SRV",
            Status.PASS.value,
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
                Status.PASS.value,
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
                Status.UNKNOWN.value,
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        has_found = any(entries for entries in found.values())
        has_mismatch = bool(mismatched) or bool(extra) or (missing and has_found)
        if has_mismatch:
            return RecordCheck(
                "SRV",
                Status.FAIL.value,
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
                Status.WARN.value,
                "SRV optional records missing",
                {"missing": missing, "found": found, "expected": expected},
                optional=True,
            )

        return RecordCheck(
            "SRV",
            Status.PASS.value,
            "SRV optional records present",
            {"records": expected},
            optional=True,
        )
