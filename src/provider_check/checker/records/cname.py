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
