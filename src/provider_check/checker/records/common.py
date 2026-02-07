"""Record normalization helpers."""

from __future__ import annotations

import ipaddress
from typing import Iterable, List


class NormalizationMixin:
    """Normalize record values for comparisons."""

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Normalize a hostname to lowercase and ensure a trailing dot.

        Args:
            host (str): Hostname to normalize.

        Returns:
            str: Normalized hostname ending in a dot.
        """
        return host.rstrip(".").lower() + "."

    def _normalize_txt_name(self, name: str) -> str:
        """Normalize a TXT record name to a fully qualified domain.

        Args:
            name (str): TXT record name or template.

        Returns:
            str: Fully qualified TXT record name without trailing dot.
        """
        trimmed = name.strip()
        if trimmed == "@":
            return self.domain
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if trimmed.endswith("."):
            return trimmed[:-1]
        if "." in trimmed:
            return trimmed
        return f"{trimmed}.{self.domain}"

    def _normalize_record_name(self, name: str) -> str:
        """Normalize a record name to a fully qualified domain.

        Args:
            name (str): Record name or template.

        Returns:
            str: Fully qualified record name without trailing dot.
        """
        trimmed = name.strip()
        if trimmed == "@":
            return self.domain
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if trimmed.endswith("."):
            return trimmed[:-1]
        if trimmed.endswith(self.domain):
            return trimmed
        return f"{trimmed}.{self.domain}"

    @staticmethod
    def _normalize_address_value(value: str) -> str:
        """Normalize an IP address value for comparison.

        Args:
            value (str): Raw IP address value.

        Returns:
            str: Normalized IP address string.
        """
        trimmed = str(value).strip()
        try:
            return ipaddress.ip_address(trimmed).compressed
        except ValueError:
            return trimmed.lower()

    @staticmethod
    def _normalize_caa_value(value: str, tag: str) -> str:
        """Normalize a CAA value for comparison.

        Args:
            value (str): Raw CAA value.
            tag (str): CAA tag associated with the value.

        Returns:
            str: Normalized CAA value.
        """
        normalized = " ".join(str(value).split()).strip()
        tag_normalized = str(tag).strip().lower()
        if tag_normalized in {"issue", "issuewild"}:
            return normalized.lower()
        return normalized

    def _normalize_caa_entry(self, flags: int, tag: str, value: str) -> tuple[int, str, str]:
        """Normalize a CAA entry for comparison.

        Args:
            flags (int): CAA flags value.
            tag (str): CAA tag value.
            value (str): CAA value string.

        Returns:
            tuple[int, str, str]: Normalized tuple for matching.
        """
        normalized_tag = str(tag).strip().lower()
        return (
            int(flags),
            normalized_tag,
            self._normalize_caa_value(str(value), normalized_tag),
        )

    def _normalize_mailto(self, value: str) -> str:
        """Normalize a DMARC mailto value.

        Args:
            value (str): Mailto value with or without "mailto:" prefix.

        Returns:
            str: Normalized mailto URI in lowercase.

        Raises:
            ValueError: If the mailto value is empty.
        """
        trimmed = value.strip()
        if "{domain}" in trimmed:
            trimmed = trimmed.replace("{domain}", self.domain)
        if not trimmed:
            raise ValueError("DMARC mailto value must not be empty")
        if trimmed.lower().startswith("mailto:"):
            address = trimmed[len("mailto:") :].strip()
        else:
            address = trimmed
        if not address:
            raise ValueError("DMARC mailto value must include an address")
        return f"mailto:{address}".lower()

    def _normalize_mailto_list(self, values: Iterable[str]) -> List[str]:
        """Normalize and de-duplicate a list of mailto values.

        Args:
            values (Iterable[str]): Mailto values to normalize.

        Returns:
            List[str]: Normalized, de-duplicated mailto URIs.
        """
        normalized: List[str] = []
        for value in values:
            normalized_value = self._normalize_mailto(str(value))
            if normalized_value not in normalized:
                normalized.append(normalized_value)
        return normalized

    @staticmethod
    def _normalize_tlsa_association(value: str) -> str:
        """Normalize TLSA certificate association data for comparison.

        Args:
            value (str): Raw certificate association data.

        Returns:
            str: Normalized certificate association string.
        """
        return "".join(str(value).split()).lower()

    def _normalize_tlsa_entry(
        self,
        usage: int,
        selector: int,
        matching_type: int,
        certificate_association: str,
    ) -> tuple[int, int, int, str]:
        """Normalize a TLSA entry for comparison.

        Args:
            usage (int): TLSA usage value.
            selector (int): TLSA selector value.
            matching_type (int): TLSA matching type value.
            certificate_association (str): TLSA certificate association data.

        Returns:
            tuple[int, int, int, str]: Normalized tuple for matching.
        """
        return (
            int(usage),
            int(selector),
            int(matching_type),
            self._normalize_tlsa_association(certificate_association),
        )
