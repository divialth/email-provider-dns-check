"""MX record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck


class MxChecksMixin:
    """Validate MX records."""

    def _normalize_mx_hosts(self, records: List[object]) -> set[str]:
        """Normalize MX host names from record entries.

        Args:
            records (List[object]): MX record entries.

        Returns:
            set[str]: Normalized host names.
        """
        return {self._normalize_host(entry.host) for entry in records}

    def _mx_priorities(self, records: List[object]) -> Dict[str, int]:
        """Build a mapping of MX host -> priority for entries with priorities.

        Args:
            records (List[object]): MX record entries.

        Returns:
            Dict[str, int]: Host-to-priority mapping.
        """
        return {
            self._normalize_host(entry.host): int(entry.priority)
            for entry in records
            if entry.priority is not None
        }

    def _load_mx_records(self) -> tuple[set[str], set[str], Dict[str, int]]:
        """Load expected MX host names and priorities.

        Returns:
            tuple[set[str], set[str], Dict[str, int]]: Required hosts, optional hosts, and
                required priorities mapping.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")
        required_hosts = self._normalize_mx_hosts(self.provider.mx.required)
        optional_hosts = self._normalize_mx_hosts(self.provider.mx.optional)
        required_priorities = self._mx_priorities(self.provider.mx.required)
        return required_hosts, optional_hosts, required_priorities

    def check_mx(self) -> RecordCheck:
        """Validate MX records for the configured provider.

        Returns:
            RecordCheck: Result of the MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        required_hosts, optional_hosts, required_priorities = self._load_mx_records()
        allowed_hosts = required_hosts | optional_hosts

        if not required_hosts:
            return RecordCheck.pass_(
                "MX",
                "No MX records required",
                {"expected": sorted(required_hosts)},
            )

        try:
            mx_records = self.resolver.get_mx(self.domain)
        except DnsLookupError as err:
            return RecordCheck.unknown("MX", "DNS lookup failed", {"error": str(err)})

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
            return RecordCheck.fail(
                "MX",
                "No MX records found",
                {"expected": sorted(required_hosts)},
            )

        missing = required_hosts - found
        extra = found - allowed_hosts

        mismatched: Dict[str, Dict[str, object]] = {}
        for host, priority in required_priorities.items():
            found_values = found_priorities.get(host, [])
            if found_values and priority in found_values:
                continue
            if host in found:
                mismatched[host] = {"expected": priority, "found": sorted(found_values)}

        if self.strict:
            if missing or extra or mismatched:
                message = "MX records do not exactly match required configuration"
                details: Dict[str, object] = {
                    "expected": sorted(required_hosts),
                    "found": sorted(found),
                }
                if mismatched:
                    details["mismatched"] = mismatched
                if extra:
                    details["extra"] = sorted(extra)
                return RecordCheck.fail("MX", message, details)
            return RecordCheck.pass_(
                "MX",
                "MX records match required configuration",
                {"found": sorted(found)},
            )

        if missing:
            return RecordCheck.fail(
                "MX",
                "Missing required MX host(s)",
                {"missing": sorted(missing), "found": sorted(found)},
            )
        if mismatched:
            details = {"mismatched": mismatched, "found": sorted(found)}
            if extra:
                details["extra"] = sorted(extra)
            return RecordCheck.warn("MX", "MX priorities differ from expected", details)
        if extra:
            return RecordCheck.warn(
                "MX",
                "Additional MX hosts present; required hosts found",
                {"extra": sorted(extra), "found": sorted(found)},
            )
        return RecordCheck.pass_("MX", "Required MX records present", {"found": sorted(found)})

    def check_mx_optional(self) -> RecordCheck:
        """Validate optional MX records for the configured provider.

        Returns:
            RecordCheck: Result of the optional MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")

        optional_records = self.provider.mx.optional
        if not optional_records:
            return RecordCheck.pass_(
                "MX",
                "No optional MX records required",
                {},
                optional=True,
            )

        try:
            mx_records = self.resolver.get_mx(self.domain)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "MX",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        expected_hosts = self._normalize_mx_hosts(optional_records)
        expected_priorities = self._mx_priorities(optional_records)

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

        missing = expected_hosts - found
        mismatched: Dict[str, Dict[str, object]] = {}
        for host, priority in expected_priorities.items():
            found_values = found_priorities.get(host, [])
            if found_values and priority in found_values:
                continue
            if host in found:
                mismatched[host] = {"expected": priority, "found": sorted(found_values)}

        if missing or mismatched:
            details: Dict[str, object] = {
                "expected": sorted(expected_hosts),
                "found": sorted(found),
            }
            if missing:
                details["missing"] = sorted(missing)
            if mismatched:
                details["mismatched"] = mismatched
            return RecordCheck.warn(
                "MX",
                "Optional MX records missing",
                details,
                optional=True,
            )

        return RecordCheck.pass_(
            "MX",
            "Optional MX records present",
            {"expected": sorted(expected_hosts)},
            optional=True,
        )
