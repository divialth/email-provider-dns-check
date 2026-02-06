"""DKIM record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from ...status import Status
from .models import RecordCheck


class DkimChecksMixin:
    """Validate DKIM selectors."""

    def check_dkim(self) -> RecordCheck:
        """Validate DKIM selectors for the configured provider.

        Returns:
            RecordCheck: Result of the DKIM validation.

        Raises:
            ValueError: If the provider does not define DKIM requirements.
        """
        if not self.provider.dkim:
            raise ValueError("DKIM configuration not available for provider")

        missing: List[str] = []
        wrong_target: Dict[str, str] = {}
        selectors_map: Dict[str, str] = {}
        expected_selectors: List[str] = []
        found_selectors: List[str] = []
        dkim_required = self.provider.dkim.required
        if dkim_required.record_type == "cname":
            template = dkim_required.target_template
            if not template:
                return RecordCheck.unknown(
                    "DKIM",
                    "Invalid DKIM target template",
                    {"error": "missing target_template"},
                )
            for selector in dkim_required.selectors:
                name = f"{selector}._domainkey.{self.domain}"
                try:
                    expected_target = template.format(selector=selector)
                except (KeyError, ValueError) as err:
                    return RecordCheck.unknown(
                        "DKIM",
                        "Invalid DKIM target template",
                        {"error": str(err), "template": template},
                    )
                expected_target = self._normalize_host(expected_target)
                selectors_map[name] = expected_target
                expected_selectors.append(name)

                try:
                    target = self.resolver.get_cname(name)
                except DnsLookupError as err:
                    return RecordCheck.unknown("DKIM", "DNS lookup failed", {"error": str(err)})
                if target is None:
                    missing.append(name)
                    continue
                if target.lower() != expected_target.lower():
                    wrong_target[name] = target
                    found_selectors.append(name)
                    continue
                found_selectors.append(name)
        else:
            expected_values = {
                selector: value for selector, value in dkim_required.txt_values.items()
            }
            for selector in dkim_required.selectors:
                name = f"{selector}._domainkey.{self.domain}"
                expected_selectors.append(name)
                expected_value = expected_values.get(selector)
                selectors_map[name] = expected_value or "present"
                try:
                    txt_records = self.resolver.get_txt(name)
                except DnsLookupError as err:
                    return RecordCheck.unknown("DKIM", "DNS lookup failed", {"error": str(err)})
                if not txt_records:
                    missing.append(name)
                    continue
                found_selectors.append(name)
                if expected_value:
                    normalized_expected = " ".join(expected_value.split()).lower()
                    normalized_found = [" ".join(record.split()).lower() for record in txt_records]
                    if normalized_expected not in normalized_found:
                        wrong_target[name] = txt_records[0]
                        continue
                    selectors_map[name] = expected_value
                else:
                    selectors_map[name] = "present"

        if missing or wrong_target:
            status = Status.FAIL if self.strict or missing else Status.WARN
            return RecordCheck.with_status(
                "DKIM",
                status,
                "DKIM selectors not fully aligned",
                {
                    "missing": missing,
                    "mismatched": wrong_target,
                    "expected_selectors": expected_selectors,
                    "found_selectors": found_selectors,
                    "expected_targets": selectors_map,
                },
            )

        return RecordCheck.pass_(
            "DKIM",
            "All DKIM selectors configured",
            {"selectors": selectors_map},
        )
