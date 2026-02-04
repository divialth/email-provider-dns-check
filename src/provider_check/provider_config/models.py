"""Dataclasses for provider configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class MXConfig:
    """Define MX record requirements for a provider.

    Attributes:
        hosts (List[str]): Required MX hostnames.
        priorities (Dict[str, int]): Expected MX priorities by host.
    """

    hosts: List[str]
    priorities: Dict[str, int]


@dataclass(frozen=True)
class SPFConfig:
    """Define SPF record requirements for a provider.

    Attributes:
        required_includes (List[str]): Required include mechanisms.
        strict_record (Optional[str]): Exact SPF record when strict mode is enabled.
        required_mechanisms (List[str]): Required SPF mechanisms.
        allowed_mechanisms (List[str]): Allowed SPF mechanisms beyond required ones.
        required_modifiers (Dict[str, str]): Required SPF modifiers (e.g., redirect).
    """

    required_includes: List[str]
    strict_record: Optional[str]
    required_mechanisms: List[str]
    allowed_mechanisms: List[str]
    required_modifiers: Dict[str, str]


@dataclass(frozen=True)
class DKIMConfig:
    """Define DKIM selector requirements for a provider.

    Attributes:
        selectors (List[str]): DKIM selector names to validate.
        record_type (str): DKIM record type ("cname" or "txt").
        target_template (Optional[str]): Target template for CNAME records.
        txt_values (Dict[str, str]): Expected TXT values keyed by selector.
    """

    selectors: List[str]
    record_type: str
    target_template: Optional[str]
    txt_values: Dict[str, str]


@dataclass(frozen=True)
class CNAMEConfig:
    """Define CNAME record requirements for a provider.

    Attributes:
        records (Dict[str, str]): Mapping of record name to expected target.
        records_optional (Dict[str, str]): Optional record mapping.
    """

    records: Dict[str, str]
    records_optional: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AddressConfig:
    """Define A/AAAA record requirements for a provider.

    Attributes:
        records (Dict[str, List[str]]): Mapping of record name to expected IP values.
        records_optional (Dict[str, List[str]]): Optional record mapping.
    """

    records: Dict[str, List[str]]
    records_optional: Dict[str, List[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class CAARecord:
    """Define a single CAA record entry.

    Attributes:
        flags (int): CAA flags value.
        tag (str): CAA tag (issue, issuewild, iodef).
        value (str): CAA value string.
    """

    flags: int
    tag: str
    value: str


@dataclass(frozen=True)
class CAAConfig:
    """Define CAA record requirements for a provider.

    Attributes:
        records (Dict[str, List[CAARecord]]): CAA records keyed by name.
        records_optional (Dict[str, List[CAARecord]]): Optional CAA records keyed by name.
    """

    records: Dict[str, List[CAARecord]]
    records_optional: Dict[str, List[CAARecord]] = field(default_factory=dict)


@dataclass(frozen=True)
class SRVRecord:
    """Define a single SRV record entry.

    Attributes:
        priority (int): SRV priority value.
        weight (int): SRV weight value.
        port (int): SRV port value.
        target (str): SRV target hostname.
    """

    priority: int
    weight: int
    port: int
    target: str


@dataclass(frozen=True)
class SRVConfig:
    """Define SRV record requirements for a provider.

    Attributes:
        records (Dict[str, List[SRVRecord]]): SRV records keyed by name.
        records_optional (Dict[str, List[SRVRecord]]): Optional SRV records keyed by name.
    """

    records: Dict[str, List[SRVRecord]]
    records_optional: Dict[str, List[SRVRecord]] = field(default_factory=dict)


@dataclass(frozen=True)
class TXTConfig:
    """Define TXT record requirements for a provider.

    Attributes:
        required (Dict[str, List[str]]): Required TXT values keyed by record name.
        verification_required (bool): Whether user verification TXT is required.
    """

    required: Dict[str, List[str]]
    verification_required: bool = False


@dataclass(frozen=True)
class DMARCConfig:
    """Define DMARC record requirements for a provider.

    Attributes:
        default_policy (str): Default DMARC policy (p=).
        required_rua (List[str]): Required rua mailto URIs.
        required_ruf (List[str]): Required ruf mailto URIs.
        required_tags (Dict[str, str]): Required DMARC tags and values.
        rua_required (bool): Whether rua is required at all.
        ruf_required (bool): Whether ruf is required at all.
    """

    default_policy: str
    required_rua: List[str]
    required_ruf: List[str]
    required_tags: Dict[str, str]
    rua_required: bool = False
    ruf_required: bool = False


@dataclass(frozen=True)
class ProviderVariable:
    """Describe a provider-specific variable used in templates.

    Attributes:
        name (str): Variable name.
        required (bool): Whether the variable is required.
        default (Optional[str]): Default value when not required.
        description (Optional[str]): Human-readable description.
    """

    name: str
    required: bool = False
    default: Optional[str] = None
    description: Optional[str] = None


@dataclass(frozen=True)
class ProviderConfig:
    """Store a fully parsed provider configuration.

    Attributes:
        provider_id (str): Provider identifier.
        name (str): Provider display name.
        version (str): Provider configuration version.
        mx (Optional[MXConfig]): MX requirements.
        spf (Optional[SPFConfig]): SPF requirements.
        dkim (Optional[DKIMConfig]): DKIM requirements.
        a (Optional[AddressConfig]): A record requirements.
        aaaa (Optional[AddressConfig]): AAAA record requirements.
        cname (Optional[CNAMEConfig]): CNAME requirements.
        caa (Optional[CAAConfig]): CAA requirements.
        srv (Optional[SRVConfig]): SRV requirements.
        txt (Optional[TXTConfig]): TXT requirements.
        dmarc (Optional[DMARCConfig]): DMARC requirements.
        short_description (Optional[str]): Short provider description.
        long_description (Optional[str]): Long provider description.
        variables (Dict[str, ProviderVariable]): Provider variable definitions.
    """

    provider_id: str
    name: str
    version: str
    mx: Optional[MXConfig]
    spf: Optional[SPFConfig]
    dkim: Optional[DKIMConfig]
    a: Optional[AddressConfig] = None
    aaaa: Optional[AddressConfig] = None
    cname: Optional[CNAMEConfig] = None
    caa: Optional[CAAConfig] = None
    srv: Optional[SRVConfig] = None
    txt: Optional[TXTConfig] = None
    dmarc: Optional[DMARCConfig] = None
    short_description: Optional[str] = None
    long_description: Optional[str] = None
    variables: Dict[str, ProviderVariable] = field(default_factory=dict)
