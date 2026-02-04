"""TXT record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class TxtChecksMixin:
    """Validate TXT records."""

    def check_txt(self) -> RecordCheck:
        """Validate TXT records for the configured provider and overrides.

        Returns:
            RecordCheck: Result of the TXT validation.
        """
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
