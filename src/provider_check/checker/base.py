"""Core DNS checker orchestration."""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional

from ..dns_resolver import DnsResolver
from ..provider_config import ProviderConfig
from ..record_registry import CHECK_SPECS
from .records import RecordCheck, RecordsMixin

LOGGER = logging.getLogger("provider_check.checker")


class DNSChecker(RecordsMixin):
    """Validate provider-specific DNS records for a domain.

    Attributes:
        domain (str): Normalized domain being checked.
        provider (ProviderConfig): Provider configuration used for validation.
        resolver (DnsResolver): DNS resolver used for lookups.
        strict (bool): Whether to enforce exact matches with no extras.
        dmarc_policy (str): DMARC policy to require (p=).
        dmarc_rua_mailto (List[str]): Required rua mailto URIs.
        dmarc_ruf_mailto (List[str]): Required ruf mailto URIs.
        dmarc_required_tags (Dict[str, str]): Required DMARC tag overrides.
        spf_policy (str): SPF policy enforcement ("hardfail" or "softfail").
        additional_spf_includes (List[str]): Additional SPF include mechanisms.
        additional_spf_ip4 (List[str]): Additional SPF ip4 mechanisms.
        additional_spf_ip6 (List[str]): Additional SPF ip6 mechanisms.
        additional_txt (Dict[str, Iterable[str]]): Additional required TXT records.
        additional_txt_verification (Dict[str, Iterable[str]]): Extra TXT verification records.
        skip_txt_verification (bool): Skip provider-required TXT verification checks.
    """

    def __init__(
        self,
        domain: str,
        provider: ProviderConfig,
        resolver: Optional[DnsResolver] = None,
        *,
        strict: bool = False,
        dmarc_rua_mailto: Optional[Iterable[str]] = None,
        dmarc_ruf_mailto: Optional[Iterable[str]] = None,
        dmarc_policy: Optional[str] = None,
        dmarc_required_tags: Optional[Dict[str, str]] = None,
        spf_policy: str = "hardfail",
        additional_spf_includes: Optional[Iterable[str]] = None,
        additional_spf_ip4: Optional[Iterable[str]] = None,
        additional_spf_ip6: Optional[Iterable[str]] = None,
        additional_txt: Optional[Dict[str, Iterable[str]]] = None,
        additional_txt_verification: Optional[Dict[str, Iterable[str]]] = None,
        skip_txt_verification: bool = False,
    ) -> None:
        """Initialize a DNSChecker for a domain and provider.

        Args:
            domain (str): Domain to validate.
            provider (ProviderConfig): Provider configuration to enforce.
            resolver (Optional[DnsResolver]): DNS resolver to use.
            strict (bool): If True, require exact matches and no extras.
            dmarc_rua_mailto (Optional[Iterable[str]]): Required DMARC rua mailto URIs.
            dmarc_ruf_mailto (Optional[Iterable[str]]): Required DMARC ruf mailto URIs.
            dmarc_policy (Optional[str]): Override DMARC policy (p=).
            dmarc_required_tags (Optional[Dict[str, str]]): DMARC tag overrides to require.
            spf_policy (str): SPF policy ("hardfail" -> -all, "softfail" -> ~all).
            additional_spf_includes (Optional[Iterable[str]]): Additional SPF include entries.
            additional_spf_ip4 (Optional[Iterable[str]]): Additional SPF ip4 entries.
            additional_spf_ip6 (Optional[Iterable[str]]): Additional SPF ip6 entries.
            additional_txt (Optional[Dict[str, Iterable[str]]]): Additional required TXT values.
            additional_txt_verification (Optional[Dict[str, Iterable[str]]]): TXT verification values.
            skip_txt_verification (bool): Skip provider-required TXT verification checks.

        Raises:
            ValueError: If a DMARC mailto value is empty after normalization.
        """
        self.domain = domain.lower().strip()
        self.provider = provider
        self.resolver = resolver or DnsResolver()
        self.strict = strict

        dmarc_default_policy = "reject"
        if provider.dmarc:
            dmarc_default_policy = provider.dmarc.default_policy

        self.dmarc_policy = (dmarc_policy or dmarc_default_policy).lower()
        self.dmarc_rua_mailto = self._normalize_mailto_list(dmarc_rua_mailto or [])
        self._dmarc_rua_override = bool(self.dmarc_rua_mailto)
        self.dmarc_ruf_mailto = self._normalize_mailto_list(dmarc_ruf_mailto or [])
        self._dmarc_ruf_override = bool(self.dmarc_ruf_mailto)
        self.dmarc_required_tags: Dict[str, str] = {}
        if provider.dmarc:
            self.dmarc_required_tags = {
                str(key).lower(): str(value) for key, value in provider.dmarc.required_tags.items()
            }
        if dmarc_required_tags:
            for key, value in dmarc_required_tags.items():
                self.dmarc_required_tags[str(key).lower()] = str(value)
        self.spf_policy = spf_policy.lower()
        self.additional_spf_includes = list(additional_spf_includes or [])
        self.additional_spf_ip4 = list(additional_spf_ip4 or [])
        self.additional_spf_ip6 = list(additional_spf_ip6 or [])
        self.additional_txt = {
            str(name): [str(value) for value in values]
            for name, values in (additional_txt or {}).items()
        }
        self.additional_txt_verification = {
            str(name): [str(value) for value in values]
            for name, values in (additional_txt_verification or {}).items()
        }
        self.skip_txt_verification = skip_txt_verification

    def run_checks(self) -> List[RecordCheck]:
        """Run all enabled DNS checks for the configured provider.

        Returns:
            List[RecordCheck]: Ordered list of check results.
        """
        LOGGER.info(
            "Running DNS checks for %s with provider %s (v%s)",
            self.domain,
            self.provider.name,
            self.provider.version,
        )
        checks: List[tuple[str, callable]] = []
        for spec in CHECK_SPECS:
            if spec.enabled_when(self):
                checks.append((spec.record_type, getattr(self, spec.check_method)))

        if not checks:
            LOGGER.info("No checks enabled for %s", self.domain)
            return []

        LOGGER.debug("Enabled checks: %s", ", ".join(name for name, _check in checks))
        results: List[RecordCheck] = []
        for name, check in checks:
            LOGGER.debug("Starting %s check", name)
            result = check()
            LOGGER.info("%s: %s - %s", result.record_type, result.status.value, result.message)
            if result.details:
                LOGGER.debug("%s details: %s", result.record_type, result.details)
            results.append(result)
        return results
