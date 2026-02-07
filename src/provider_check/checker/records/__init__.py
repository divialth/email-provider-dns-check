"""Core DNS validation logic."""

from __future__ import annotations

import logging

from .address import AddressChecksMixin
from .caa import CaaChecksMixin
from .cname import CnameChecksMixin
from .common import NormalizationMixin
from .dkim import DkimChecksMixin
from .dmarc import DmarcChecksMixin
from .models import RecordCheck
from .mx import MxChecksMixin
from .ptr import PtrChecksMixin
from .spf import SpfChecksMixin
from .srv import SrvChecksMixin
from .tlsa import TlsaChecksMixin
from .txt import TxtChecksMixin

LOGGER = logging.getLogger("provider_check.checker")


class RecordsMixin(
    NormalizationMixin,
    MxChecksMixin,
    AddressChecksMixin,
    PtrChecksMixin,
    SpfChecksMixin,
    DkimChecksMixin,
    CnameChecksMixin,
    CaaChecksMixin,
    SrvChecksMixin,
    TlsaChecksMixin,
    TxtChecksMixin,
    DmarcChecksMixin,
):
    """Mixin that implements provider-specific DNS record checks.

    Attributes:
        domain (str): Normalized domain being checked.
        provider (ProviderConfig): Provider configuration used for validation.
        resolver (DnsResolver): DNS resolver used for lookups.
        strict (bool): Whether to enforce exact matches with no extras.
        dmarc_policy (str): DMARC policy to require (p=).
        dmarc_rua_mailto (List[str]): Required rua mailto URIs.
        dmarc_ruf_mailto (List[str]): Required ruf mailto URIs.
        dmarc_required_tags (Dict[str, str]): Required DMARC tag overrides.
        spf_policy (str): SPF policy enforcement
            ("hardfail", "softfail", "neutral", or "allow").
        additional_spf_includes (List[str]): Additional SPF include mechanisms.
        additional_spf_ip4 (List[str]): Additional SPF ip4 mechanisms.
        additional_spf_ip6 (List[str]): Additional SPF ip6 mechanisms.
        additional_txt (Dict[str, Iterable[str]]): Additional required TXT records.
        additional_txt_verification (Dict[str, Iterable[str]]): Extra TXT verification records.
        skip_txt_verification (bool): Skip provider-required TXT verification checks.
    """


__all__ = [
    "RecordCheck",
    "RecordsMixin",
]
