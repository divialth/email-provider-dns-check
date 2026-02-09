"""CNAME record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from ...status import Status
from .models import RecordCheck


class CnameChecksMixin:
    """Validate CNAME records."""

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
                self.provider.cname.required
            )
        except DnsLookupError as err:
            return RecordCheck.unknown("CNAME", "DNS lookup failed", {"error": str(err)})

        if missing or mismatched:
            return RecordCheck.fail(
                "CNAME",
                "CNAME records do not match required configuration",
                {
                    "missing": missing,
                    "mismatched": mismatched,
                    "expected": expected_targets,
                    "found": found_targets,
                },
            )

        return RecordCheck.pass_(
            "CNAME",
            "Required CNAME records present",
            {"expected": expected_targets},
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

        optional_records = self.provider.cname.optional
        if not optional_records:
            return RecordCheck.pass_(
                "CNAME",
                "No optional CNAME records required",
                {},
                optional=True,
            )

        try:
            missing, mismatched, expected_targets, found_targets = self._evaluate_cname_records(
                optional_records
            )
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "CNAME",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        if missing or mismatched:
            status = Status.FAIL if mismatched else Status.WARN
            message = (
                "CNAME optional records mismatched"
                if mismatched
                else "CNAME optional records missing"
            )
            return RecordCheck.with_status(
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

        return RecordCheck.pass_(
            "CNAME",
            "CNAME optional records present",
            {"expected": expected_targets},
            optional=True,
        )

    def _evaluate_cname_match_rules(
        self, rules: Dict[str, "CNAMEMatchRule"]
    ) -> tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        """Evaluate deprecated/forbidden CNAME rules.

        Args:
            rules (Dict[str, CNAMEMatchRule]): Match rules keyed by record name.

        Returns:
            tuple[Dict[str, str], Dict[str, str], Dict[str, str]]: Matched, expected,
                and found values keyed by record name.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        matched: Dict[str, str] = {}
        expected: Dict[str, str] = {}
        found: Dict[str, str] = {}
        for name, rule in rules.items():
            lookup_name = self._normalize_record_name(name)
            found_target = self.resolver.get_cname(lookup_name)
            if found_target is not None:
                found[lookup_name] = found_target
            if rule.match == "any":
                if found_target is not None:
                    matched[lookup_name] = found_target
                continue
            if rule.target is None:
                continue
            expected_target = self._normalize_host(rule.target)
            expected[lookup_name] = expected_target
            if found_target and self._normalize_host(found_target) == expected_target:
                matched[lookup_name] = found_target
        return matched, expected, found

    def _check_cname_negative(
        self, rules: Dict[str, "CNAMEMatchRule"], *, scope: str
    ) -> RecordCheck:
        """Run deprecated/forbidden checks for CNAME records.

        Args:
            rules (Dict[str, CNAMEMatchRule]): Match rules keyed by record name.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific CNAME match result.
        """
        if not rules:
            return RecordCheck.pass_(
                "CNAME",
                f"No {scope} CNAME records configured",
                {},
                scope=scope,
            )
        try:
            matched, expected, found = self._evaluate_cname_match_rules(rules)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "CNAME",
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        if matched:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                "CNAME",
                f"{scope.capitalize()} CNAME records are present",
                {"matched": matched, "expected": expected, "found": found},
                scope=scope,
            )
        return RecordCheck.pass_(
            "CNAME",
            f"No {scope} CNAME records present",
            {"expected": expected},
            scope=scope,
        )

    def check_cname_deprecated(self) -> RecordCheck:
        """Validate deprecated CNAME records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated CNAME validation.

        Raises:
            ValueError: If the provider does not define CNAME requirements.
        """
        if not self.provider.cname:
            raise ValueError("CNAME configuration not available for provider")
        return self._check_cname_negative(self.provider.cname.deprecated, scope="deprecated")

    def check_cname_forbidden(self) -> RecordCheck:
        """Validate forbidden CNAME records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden CNAME validation.

        Raises:
            ValueError: If the provider does not define CNAME requirements.
        """
        if not self.provider.cname:
            raise ValueError("CNAME configuration not available for provider")
        return self._check_cname_negative(self.provider.cname.forbidden, scope="forbidden")
