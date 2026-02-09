"""CAA record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class CaaChecksMixin:
    """Validate CAA records."""

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
                self.provider.caa.required, strict=self.strict
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("CAA", "DNS lookup failed", {"error": str(err)})

        if self.strict and (missing or extra):
            details: Dict[str, object] = {"expected": expected, "found": found}
            if missing:
                details["missing"] = missing
            if extra:
                details["extra"] = extra
            return RecordCheck.fail(
                "CAA",
                "CAA records do not exactly match required configuration",
                details,
            )

        if missing:
            return RecordCheck.fail(
                "CAA",
                "Missing required CAA records",
                {"missing": missing, "expected": expected, "found": found},
            )

        return RecordCheck.pass_(
            "CAA",
            "Required CAA records present",
            {"expected": expected},
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

        optional_records = self.provider.caa.optional
        if not optional_records:
            return RecordCheck.pass_(
                "CAA",
                "No optional CAA records required",
                {},
                optional=True,
            )

        try:
            missing, _extra, expected, found = self._evaluate_caa_records(
                optional_records, strict=False
            )
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "CAA",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        if missing:
            return RecordCheck.warn(
                "CAA",
                "CAA optional records missing",
                {"missing": missing, "expected": expected, "found": found},
                optional=True,
            )

        return RecordCheck.pass_(
            "CAA",
            "CAA optional records present",
            {"expected": expected},
            optional=True,
        )

    def _evaluate_caa_match_rules(self, rules: Dict[str, "CAAMatchRule"]) -> tuple[
        Dict[str, List[tuple[int, str, str]]],
        Dict[str, List[tuple[int, str, str]]],
        Dict[str, List[tuple[int, str, str]]],
    ]:
        """Evaluate deprecated/forbidden CAA rules.

        Args:
            rules (Dict[str, CAAMatchRule]): Match rules keyed by record name.

        Returns:
            tuple[Dict[str, List[tuple[int, str, str]]], ...]: Matched, expected, and found
                entries keyed by record name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        matched: Dict[str, List[tuple[int, str, str]]] = {}
        expected: Dict[str, List[tuple[int, str, str]]] = {}
        found: Dict[str, List[tuple[int, str, str]]] = {}
        for name, rule in rules.items():
            lookup_name = self._normalize_record_name(name)
            found_entries = [
                self._normalize_caa_entry(flags, tag, value)
                for flags, tag, value in self.resolver.get_caa(lookup_name)
            ]
            found[lookup_name] = sorted(found_entries)
            expected_entries = [
                self._normalize_caa_entry(entry.flags, entry.tag, entry.value)
                for entry in rule.entries
            ]
            expected[lookup_name] = sorted(expected_entries)
            if rule.match == "any":
                if found_entries:
                    matched[lookup_name] = sorted(found_entries)
                continue
            overlap = sorted(set(expected_entries) & set(found_entries))
            if overlap:
                matched[lookup_name] = overlap
        return matched, expected, found

    def _check_caa_negative(self, rules: Dict[str, "CAAMatchRule"], *, scope: str) -> RecordCheck:
        """Run deprecated/forbidden checks for CAA records.

        Args:
            rules (Dict[str, CAAMatchRule]): Match rules keyed by record name.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific CAA match result.
        """
        if not rules:
            return RecordCheck.pass_(
                "CAA",
                f"No {scope} CAA records configured",
                {},
                scope=scope,
            )
        try:
            matched, expected, found = self._evaluate_caa_match_rules(rules)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "CAA",
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        if matched:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                "CAA",
                f"{scope.capitalize()} CAA records are present",
                {"matched": matched, "expected": expected, "found": found},
                scope=scope,
            )
        return RecordCheck.pass_(
            "CAA",
            f"No {scope} CAA records present",
            {"expected": expected},
            scope=scope,
        )

    def check_caa_deprecated(self) -> RecordCheck:
        """Validate deprecated CAA records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated CAA validation.

        Raises:
            ValueError: If the provider does not define CAA requirements.
        """
        if not self.provider.caa:
            raise ValueError("CAA configuration not available for provider")
        return self._check_caa_negative(self.provider.caa.deprecated, scope="deprecated")

    def check_caa_forbidden(self) -> RecordCheck:
        """Validate forbidden CAA records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden CAA validation.

        Raises:
            ValueError: If the provider does not define CAA requirements.
        """
        if not self.provider.caa:
            raise ValueError("CAA configuration not available for provider")
        return self._check_caa_negative(self.provider.caa.forbidden, scope="forbidden")
