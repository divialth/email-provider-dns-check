"""DMARC record checks."""

from __future__ import annotations

from typing import Dict, List

from ...dns_resolver import DnsLookupError
from ...status import Status
from .models import RecordCheck


class DmarcChecksMixin:
    """Validate DMARC records."""

    def _effective_required_rua(self) -> List[str]:
        """Determine the required rua mailto values.

        Returns:
            List[str]: Required rua mailto URIs after overrides.
        """
        if not self.provider.dmarc:
            return []
        if self._dmarc_rua_override:
            return list(self.dmarc_rua_mailto)
        return self._normalize_mailto_list(self.provider.dmarc.required_rua)

    def _effective_required_ruf(self) -> List[str]:
        """Determine the required ruf mailto values.

        Returns:
            List[str]: Required ruf mailto URIs after overrides.
        """
        if not self.provider.dmarc:
            return []
        if self._dmarc_ruf_override:
            return list(self.dmarc_ruf_mailto)
        return self._normalize_mailto_list(self.provider.dmarc.required_ruf)

    def _rua_required(self, required_rua: List[str]) -> bool:
        """Check whether rua values must be present.

        Args:
            required_rua (List[str]): Required rua entries.

        Returns:
            bool: True if rua is required.
        """
        if not self.provider.dmarc:
            return False
        if self._dmarc_rua_override:
            return True
        return self.provider.dmarc.rua_required or bool(required_rua)

    def _ruf_required(self, required_ruf: List[str]) -> bool:
        """Check whether ruf values must be present.

        Args:
            required_ruf (List[str]): Required ruf entries.

        Returns:
            bool: True if ruf is required.
        """
        if not self.provider.dmarc:
            return False
        if self._dmarc_ruf_override:
            return True
        return self.provider.dmarc.ruf_required or bool(required_ruf)

    def _expected_dmarc_value(
        self,
        required_rua: List[str],
        rua_required: bool,
        required_ruf: List[str],
        ruf_required: bool,
    ) -> str:
        """Build the expected DMARC policy string.

        Args:
            required_rua (List[str]): Required rua values.
            rua_required (bool): Whether rua is required.
            required_ruf (List[str]): Required ruf values.
            ruf_required (bool): Whether ruf is required.

        Returns:
            str: Expected DMARC record string.
        """
        policy = self.dmarc_policy
        parts = [f"v=DMARC1", f"p={policy}"]
        if rua_required:
            rua_value = ",".join(required_rua) if required_rua else "<required>"
            parts.append(f"rua={rua_value}")
        if ruf_required:
            ruf_value = ",".join(required_ruf) if required_ruf else "<required>"
            parts.append(f"ruf={ruf_value}")
        if self.dmarc_required_tags:
            for key in sorted(self.dmarc_required_tags.keys()):
                parts.append(f"{key}={self.dmarc_required_tags[key]}")
        return ";".join(parts)

    @staticmethod
    def _parse_dmarc_tokens(record: str) -> Dict[str, str]:
        """Parse a DMARC record into a tag map.

        Args:
            record (str): Raw DMARC record string.

        Returns:
            Dict[str, str]: Mapping of tag to value.
        """
        parts = [part for part in record.replace(" ", "").split(";") if "=" in part]
        return {part.split("=", 1)[0].lower(): part.split("=", 1)[1] for part in parts}

    @staticmethod
    def _parse_mailto_entries(raw_value: str) -> List[str]:
        """Parse a DMARC mailto value list.

        Args:
            raw_value (str): Comma-separated mailto entries.

        Returns:
            List[str]: Normalized mailto entries.
        """
        return [entry.strip().lower() for entry in raw_value.split(",") if entry.strip()]

    @staticmethod
    def _matches_dmarc_uri(required: str, found: str) -> bool:
        """Check if a found mailto entry satisfies a required entry.

        Args:
            required (str): Required mailto URI.
            found (str): Found mailto URI.

        Returns:
            bool: True if the found entry satisfies the requirement.
        """
        if required == found:
            return True
        if not required.startswith("mailto:") or not found.startswith("mailto:"):
            return False
        if "!" in required or "?" in required:
            return False
        if not found.startswith(required):
            return False
        suffix = found[len(required) :]
        return not suffix or suffix[0] in {"!", "?"}

    def _required_dmarc_uris_present(self, required: List[str], found: List[str]) -> bool:
        """Check that all required DMARC URIs appear in the found list.

        Args:
            required (List[str]): Required mailto URIs.
            found (List[str]): Found mailto URIs.

        Returns:
            bool: True if every required entry is present.
        """
        return all(
            any(self._matches_dmarc_uri(required_value, entry) for entry in found)
            for required_value in required
        )

    def _strict_dmarc_uris_match(self, required: List[str], found: List[str]) -> bool:
        """Check that required and found DMARC URIs match exactly.

        Args:
            required (List[str]): Required mailto URIs.
            found (List[str]): Found mailto URIs.

        Returns:
            bool: True if both sets match under DMARC matching rules.
        """
        for required_value in required:
            if not any(self._matches_dmarc_uri(required_value, entry) for entry in found):
                return False
        for entry in found:
            if not any(
                self._matches_dmarc_uri(required_value, entry) for required_value in required
            ):
                return False
        return True

    def check_dmarc(self) -> RecordCheck:
        """Validate DMARC records for the configured provider.

        Returns:
            RecordCheck: Result of the DMARC validation.

        Raises:
            ValueError: If the provider does not define DMARC requirements.
        """
        if not self.provider.dmarc:
            raise ValueError("DMARC configuration not available for provider")

        name = f"_dmarc.{self.domain}"
        try:
            txt_records = self.resolver.get_txt(name)
        except DnsLookupError as err:
            return RecordCheck.unknown("DMARC", "DNS lookup failed", {"error": str(err)})

        required_rua = self._effective_required_rua()
        rua_required = self._rua_required(required_rua)
        required_ruf = self._effective_required_ruf()
        ruf_required = self._ruf_required(required_ruf)
        expected = self._expected_dmarc_value(
            required_rua, rua_required, required_ruf, ruf_required
        )
        if not txt_records:
            return RecordCheck.fail(
                "DMARC",
                "No DMARC record found",
                {"expected": expected},
            )
        required_tags = {key: value.lower() for key, value in self.dmarc_required_tags.items()}

        for record in txt_records:
            if self.strict:
                tokens = self._parse_dmarc_tokens(record)
                if tokens.get("v", "").upper() != "DMARC1":
                    continue
                if tokens.get("p", "").lower() != self.dmarc_policy:
                    continue
                rua_entries = self._parse_mailto_entries(tokens.get("rua", ""))
                ruf_entries = self._parse_mailto_entries(tokens.get("ruf", ""))
                if rua_required:
                    if not rua_entries:
                        continue
                    if required_rua and not self._strict_dmarc_uris_match(
                        required_rua, rua_entries
                    ):
                        continue
                if ruf_required:
                    if not ruf_entries:
                        continue
                    if required_ruf and not self._strict_dmarc_uris_match(
                        required_ruf, ruf_entries
                    ):
                        continue
                missing_tags = {
                    key: value
                    for key, value in required_tags.items()
                    if tokens.get(key, "").lower() != value
                }
                if missing_tags:
                    continue
                allowed_tags = {"v", "p"}
                if rua_required:
                    allowed_tags.add("rua")
                if ruf_required:
                    allowed_tags.add("ruf")
                allowed_tags.update(required_tags.keys())
                if set(tokens.keys()) != allowed_tags:
                    continue
                return RecordCheck.pass_(
                    "DMARC",
                    "DMARC record matches strict configuration",
                    {"record": record},
                )
                continue

            tokens = self._parse_dmarc_tokens(record)
            policy = tokens.get("p", "").lower()
            rua_entries = self._parse_mailto_entries(tokens.get("rua", ""))
            ruf_entries = self._parse_mailto_entries(tokens.get("ruf", ""))

            if tokens.get("v", "").upper() != "DMARC1":
                continue
            if policy != self.dmarc_policy:
                continue
            if rua_required:
                if not rua_entries:
                    continue
                if required_rua and not self._required_dmarc_uris_present(
                    required_rua, rua_entries
                ):
                    continue
            if ruf_required:
                if not ruf_entries:
                    continue
                if required_ruf and not self._required_dmarc_uris_present(
                    required_ruf, ruf_entries
                ):
                    continue

            missing_tags = {
                key: value
                for key, value in required_tags.items()
                if tokens.get(key, "").lower() != value
            }
            if missing_tags:
                continue

            status = Status.PASS
            message = (
                "DMARC policy present"
                if not rua_entries and not ruf_entries
                else "DMARC policy and reporting tags present"
            )
            details = {"record": record}
            return RecordCheck.with_status("DMARC", status, message, details)

        return RecordCheck.fail(
            "DMARC",
            "DMARC record does not meet guidance",
            {"expected": expected, "found": txt_records},
        )
