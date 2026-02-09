"""MX record checks."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Dict, List

from ...dns_resolver import DnsLookupError
from .models import RecordCheck

if TYPE_CHECKING:
    from ...provider_config import MXNegativeRules


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

    def _collect_mx_found(self) -> tuple[set[str], Dict[str, List[int]]]:
        """Collect normalized MX hosts and priorities from DNS.

        Returns:
            tuple[set[str], Dict[str, List[int]]]: Found hosts and host priority values.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        mx_records = self.resolver.get_mx(self.domain)
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
        return found, found_priorities

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
            found, found_priorities = self._collect_mx_found()
        except DnsLookupError as err:
            return RecordCheck.unknown("MX", "DNS lookup failed", {"error": str(err)})

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
            found, found_priorities = self._collect_mx_found()
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "MX",
                "DNS lookup failed",
                {"error": str(err)},
                optional=True,
            )

        expected_hosts = self._normalize_mx_hosts(optional_records)
        expected_priorities = self._mx_priorities(optional_records)

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

    def _evaluate_mx_match_rules(
        self, rules: "MXNegativeRules"
    ) -> tuple[set[str], set[str], set[str], Dict[str, int], Dict[str, List[int]], str]:
        """Evaluate deprecated/forbidden MX rules.

        Args:
            rules (MXNegativeRules): MX rules for deprecated/forbidden matching.

        Returns:
            tuple[set[str], set[str], set[str], Dict[str, int], Dict[str, List[int]], str]:
                Matched hosts, expected hosts, found hosts, expected priorities, found
                priorities, and match mode.

        Raises:
            DnsLookupError: If DNS lookup fails.
        """
        match_mode = str(rules.policy.match).lower()
        found_hosts, found_priorities = self._collect_mx_found()
        expected_hosts: set[str] = set()
        expected_priorities: Dict[str, int] = {}
        matched_hosts: set[str] = set()

        if match_mode == "any":
            if found_hosts:
                matched_hosts = set(found_hosts)
            return (
                matched_hosts,
                expected_hosts,
                found_hosts,
                expected_priorities,
                found_priorities,
                match_mode,
            )

        expected_hosts = self._normalize_mx_hosts(rules.entries)
        expected_priorities = self._mx_priorities(rules.entries)
        for host in expected_hosts:
            if host not in found_hosts:
                continue
            expected_priority = expected_priorities.get(host)
            if expected_priority is None:
                matched_hosts.add(host)
                continue
            if expected_priority in found_priorities.get(host, []):
                matched_hosts.add(host)
        return (
            matched_hosts,
            expected_hosts,
            found_hosts,
            expected_priorities,
            found_priorities,
            match_mode,
        )

    def _check_mx_negative(self, rules: "MXNegativeRules", *, scope: str) -> RecordCheck:
        """Run deprecated/forbidden checks for MX records.

        Args:
            rules (MXNegativeRules): MX rules for deprecated/forbidden matching.
            scope (str): Result scope ("deprecated" or "forbidden").

        Returns:
            RecordCheck: Scope-specific MX match result.
        """
        match_mode = str(rules.policy.match).lower()
        if match_mode == "exact" and not rules.entries:
            return RecordCheck.pass_(
                "MX",
                f"No {scope} MX records configured",
                {},
                scope=scope,
            )
        try:
            (
                matched_hosts,
                expected_hosts,
                found_hosts,
                expected_priorities,
                found_priorities,
                mode,
            ) = self._evaluate_mx_match_rules(rules)
        except DnsLookupError as err:
            return RecordCheck.unknown(
                "MX",
                "DNS lookup failed",
                {"error": str(err)},
                scope=scope,
            )
        details: Dict[str, object] = {
            "policy": {"match": mode},
            "matched": sorted(matched_hosts),
            "expected": sorted(expected_hosts),
            "found": sorted(found_hosts),
        }
        if expected_priorities:
            details["expected_priorities"] = expected_priorities
        if found_priorities:
            details["found_priorities"] = {
                host: sorted(values) for host, values in found_priorities.items()
            }
        if matched_hosts:
            status_builder = RecordCheck.warn if scope == "deprecated" else RecordCheck.fail
            return status_builder(
                "MX",
                f"{scope.capitalize()} MX records are present",
                details,
                scope=scope,
            )
        return RecordCheck.pass_(
            "MX",
            f"No {scope} MX records present",
            details,
            scope=scope,
        )

    def check_mx_deprecated(self) -> RecordCheck:
        """Validate deprecated MX records for the configured provider.

        Returns:
            RecordCheck: Result of deprecated MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")
        return self._check_mx_negative(self.provider.mx.deprecated, scope="deprecated")

    def check_mx_forbidden(self) -> RecordCheck:
        """Validate forbidden MX records for the configured provider.

        Returns:
            RecordCheck: Result of forbidden MX validation.

        Raises:
            ValueError: If the provider does not define MX requirements.
        """
        if not self.provider.mx:
            raise ValueError("MX configuration not available for provider")
        return self._check_mx_negative(self.provider.mx.forbidden, scope="forbidden")
