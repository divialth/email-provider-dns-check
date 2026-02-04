"""MX record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class MxChecksMixin:
    """Validate MX records."""

    def check_mx(self) -> RecordCheck:
        """Validate MX records for the configured provider.

        Returns:
            RecordCheck: Result of the MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")

        try:
            mx_records = self.resolver.get_mx(self.domain)
        except DnsLookupError as err:
            return RecordCheck("MX", "UNKNOWN", "DNS lookup failed", {"error": str(err)})
        expected = {self._normalize_host(host) for host in self.provider.mx.hosts}
        found: set[str] = set()
        found_priorities: Dict[str, List[int]] = {}

        for record in mx_records:
            if isinstance(record, tuple):
                host, preference = record
            else:
                host, preference = record, None
            normalized = self._normalize_host(str(host))
            found.add(normalized)
            if preference is not None:
                found_priorities.setdefault(normalized, []).append(int(preference))

        if not found:
            return RecordCheck("MX", "FAIL", "No MX records found", {"expected": sorted(expected)})

        missing = expected - found
        extra = found - expected

        expected_priorities = {
            self._normalize_host(host): int(priority)
            for host, priority in self.provider.mx.priorities.items()
        }
        mismatched: Dict[str, Dict[str, object]] = {}
        for host, priority in expected_priorities.items():
            found_values = found_priorities.get(host, [])
            if found_values and priority in found_values:
                continue
            if host in found:
                mismatched[host] = {"expected": priority, "found": sorted(found_values)}

        if self.strict:
            if missing or extra or mismatched:
                message = "MX records do not exactly match required configuration"
                details: Dict[str, object] = {"expected": sorted(expected), "found": sorted(found)}
                if mismatched:
                    details["mismatched"] = mismatched
                if extra:
                    details["extra"] = sorted(extra)
                return RecordCheck("MX", "FAIL", message, details)
            return RecordCheck(
                "MX", "PASS", "MX records match required configuration", {"found": sorted(found)}
            )

        if missing:
            return RecordCheck(
                "MX",
                "FAIL",
                "Missing required MX host(s)",
                {"missing": sorted(missing), "found": sorted(found)},
            )
        if mismatched:
            details = {"mismatched": mismatched, "found": sorted(found)}
            if extra:
                details["extra"] = sorted(extra)
            return RecordCheck("MX", "WARN", "MX priorities differ from expected", details)
        if extra:
            return RecordCheck(
                "MX",
                "WARN",
                "Additional MX hosts present; required hosts found",
                {"extra": sorted(extra), "found": sorted(found)},
            )
        return RecordCheck("MX", "PASS", "Required MX records present", {"found": sorted(found)})
