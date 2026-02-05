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
            user_required = self.provider.txt.settings.verification_required
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
                return RecordCheck.warn(
                    "TXT",
                    "TXT record required for domain verification",
                    {"required": "user-supplied TXT verification value"},
                )
            return RecordCheck.pass_("TXT", "No TXT records required", {})

        missing_names: List[str] = []
        missing_values: Dict[str, List[str]] = {}
        found_values: Dict[str, List[str]] = {}

        for name, expected_values in required.items():
            lookup_name = self._normalize_txt_name(name)
            try:
                records = self.resolver.get_txt(lookup_name)
            except DnsLookupError as err:
                return RecordCheck.unknown("TXT", "DNS lookup failed", {"error": str(err)})
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
            return RecordCheck.fail("TXT", "TXT records missing required values", details)

        if verification_warning:
            return RecordCheck.warn(
                "TXT",
                "TXT record required for domain verification",
                {"required": "user-supplied TXT verification value"},
            )

        return RecordCheck.pass_("TXT", "TXT records present", {"required": required})

    def check_txt_optional(self) -> RecordCheck:
        """Validate optional TXT records for the configured provider.

        Returns:
            RecordCheck: Result of the optional TXT validation.

        Raises:
            ValueError: If the provider does not define TXT requirements.
        """
        if not self.provider.txt:
            raise ValueError("TXT configuration not available for provider")

        optional_records = self.provider.txt.optional
        if not optional_records:
            return RecordCheck.pass_(
                "TXT",
                "No optional TXT records required",
                {},
                optional=True,
            )

        missing_names: List[str] = []
        missing_values: Dict[str, List[str]] = {}
        found_values: Dict[str, List[str]] = {}

        for name, expected_values in optional_records.items():
            lookup_name = self._normalize_txt_name(name)
            try:
                records = self.resolver.get_txt(lookup_name)
            except DnsLookupError as err:
                return RecordCheck.unknown(
                    "TXT",
                    "DNS lookup failed",
                    {"error": str(err)},
                    optional=True,
                )
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
            if found_values:
                details["found"] = found_values
            return RecordCheck.warn(
                "TXT",
                "Optional TXT records missing",
                details,
                optional=True,
            )

        return RecordCheck.pass_(
            "TXT",
            "Optional TXT records present",
            {"required": optional_records},
            optional=True,
        )
