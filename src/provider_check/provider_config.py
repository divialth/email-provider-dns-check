"""Load provider DNS validation configuration from YAML files."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from importlib import resources
from importlib.resources import abc as resources_abc
from pathlib import Path
from typing import Dict, Iterable, List, Optional
import os

import yaml

CONFIG_DIR_NAME = "provider-dns-check"
PROVIDER_DIR_NAME = "providers"
TEMPLATE_DIR_NAME = "templates"
PROVIDER_PACKAGE = "provider_check.providers"

LOGGER = logging.getLogger(__name__)

SYSTEM_CONFIG_DIRS = [
    Path("/etc") / CONFIG_DIR_NAME,
    Path("/usr/local/etc") / CONFIG_DIR_NAME,
]


@dataclass(frozen=True)
class MXConfig:
    hosts: List[str]
    priorities: Dict[str, int]


@dataclass(frozen=True)
class SPFConfig:
    required_includes: List[str]
    strict_record: Optional[str]
    required_mechanisms: List[str]
    allowed_mechanisms: List[str]
    required_modifiers: Dict[str, str]


@dataclass(frozen=True)
class DKIMConfig:
    selectors: List[str]
    record_type: str
    target_template: Optional[str]
    txt_values: Dict[str, str]


@dataclass(frozen=True)
class TXTConfig:
    required: Dict[str, List[str]]
    verification_required: bool = False


@dataclass(frozen=True)
class DMARCConfig:
    default_policy: str
    default_rua_localpart: str
    required_rua: List[str]
    required_tags: Dict[str, str]


@dataclass(frozen=True)
class ProviderConfig:
    provider_id: str
    name: str
    version: str
    mx: Optional[MXConfig]
    spf: Optional[SPFConfig]
    dkim: Optional[DKIMConfig]
    txt: Optional[TXTConfig]
    dmarc: Optional[DMARCConfig]


def _normalize_key(value: str) -> str:
    return value.strip().lower().replace(" ", "_").replace(".", "_")


def _require_mapping(provider_id: str, field: str, value: object | None) -> dict:
    if value is None:
        raise ValueError(f"Provider config {provider_id} {field} must be a mapping")
    if not isinstance(value, dict):
        raise ValueError(f"Provider config {provider_id} {field} must be a mapping")
    return value


def _require_list(provider_id: str, field: str, value: object | None) -> list:
    if value is None:
        raise ValueError(f"Provider config {provider_id} {field} must be a list")
    if not isinstance(value, list):
        raise ValueError(f"Provider config {provider_id} {field} must be a list")
    return value


def external_config_dirs() -> List[Path]:
    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_home:
        user_dir = Path(xdg_home) / CONFIG_DIR_NAME
    else:
        user_dir = Path.home() / ".config" / CONFIG_DIR_NAME
    return [user_dir, *SYSTEM_CONFIG_DIRS]


def _external_provider_dirs() -> List[Path]:
    return [path / PROVIDER_DIR_NAME for path in external_config_dirs()]


def _iter_provider_paths_in_dir(path: Path) -> Iterable[Path]:
    if not path.is_dir():
        return
    for entry in sorted(path.iterdir(), key=lambda item: item.name):
        if entry.is_file() and entry.suffix in {".yaml", ".yml"}:
            yield entry


def _iter_packaged_paths() -> Iterable[resources_abc.Traversable]:
    base = resources.files(PROVIDER_PACKAGE)
    entries = [entry for entry in base.iterdir() if entry.is_file()]
    for entry in sorted(entries, key=lambda item: item.name):
        if entry.suffix in {".yaml", ".yml"}:
            yield entry


def _iter_provider_paths() -> Iterable[object]:
    for directory in _external_provider_dirs():
        yield from _iter_provider_paths_in_dir(directory)
    yield from _iter_packaged_paths()


def _load_yaml(path: object) -> dict:
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Provider config {path} is not a mapping")
    return data


def _is_enabled(data: dict) -> bool:
    enabled = data.get("enabled", True)
    if isinstance(enabled, bool):
        return enabled
    raise ValueError("Provider config enabled must be a boolean")


def _load_provider_from_data(provider_id: str, data: dict) -> ProviderConfig:
    version = data.get("version")
    if version is None:
        raise ValueError(f"Provider config {provider_id} is missing version")
    name = data.get("name", provider_id)
    if "records" in data:
        records = _require_mapping(provider_id, "records", data.get("records"))
    else:
        records = {}

    mx = None
    if "mx" in records:
        mx_section = _require_mapping(provider_id, "mx", records.get("mx"))
        hosts = _require_list(provider_id, "mx hosts", mx_section.get("hosts", []))
        priorities: Dict[str, int] = {}
        for entry in _require_list(provider_id, "mx records", mx_section.get("records", [])):
            if not isinstance(entry, dict):
                raise ValueError(f"Provider config {provider_id} mx records must be mappings")
            host = entry.get("host")
            priority = entry.get("priority")
            if host is None or priority is None:
                raise ValueError(
                    f"Provider config {provider_id} mx records require host and priority"
                )
            priorities[str(host)] = int(priority)
            if str(host) not in hosts:
                hosts.append(str(host))
        priorities_map = _require_mapping(
            provider_id, "mx priorities", mx_section.get("priorities", {})
        )
        for host, priority in priorities_map.items():
            priorities[str(host)] = int(priority)
            if str(host) not in hosts:
                hosts.append(str(host))
        mx = MXConfig(hosts=[str(host) for host in hosts], priorities=priorities)

    spf = None
    if "spf" in records:
        spf_section = _require_mapping(provider_id, "spf", records.get("spf"))
        required = _require_list(
            provider_id, "spf required_includes", spf_section.get("required_includes", [])
        )
        required_mechanisms = _require_list(
            provider_id,
            "spf required_mechanisms",
            spf_section.get("required_mechanisms", []),
        )
        allowed_mechanisms = _require_list(
            provider_id,
            "spf allowed_mechanisms",
            spf_section.get("allowed_mechanisms", []),
        )
        required_modifiers_raw = _require_mapping(
            provider_id,
            "spf required_modifiers",
            spf_section.get("required_modifiers", {}),
        )
        required_modifiers = {
            str(key).lower(): str(value) for key, value in required_modifiers_raw.items()
        }
        spf = SPFConfig(
            required_includes=[str(value) for value in required],
            strict_record=spf_section.get("strict_record"),
            required_mechanisms=[str(value) for value in required_mechanisms],
            allowed_mechanisms=[str(value) for value in allowed_mechanisms],
            required_modifiers=required_modifiers,
        )

    dkim = None
    if "dkim" in records:
        dkim_section = _require_mapping(provider_id, "dkim", records.get("dkim"))
        selectors = _require_list(provider_id, "dkim selectors", dkim_section.get("selectors", []))
        record_type = str(dkim_section.get("record_type", "cname")).lower()
        if record_type not in {"cname", "txt"}:
            raise ValueError(f"Provider config {provider_id} dkim record_type must be cname or txt")
        target_template = dkim_section.get("target_template")
        if record_type == "cname" and not target_template:
            raise ValueError(
                f"Provider config {provider_id} dkim requires target_template for cname"
            )
        txt_values_raw = _require_mapping(
            provider_id, "dkim txt_values", dkim_section.get("txt_values", {})
        )
        txt_values = {str(key): str(value) for key, value in txt_values_raw.items()}
        dkim = DKIMConfig(
            selectors=[str(selector) for selector in selectors],
            record_type=record_type,
            target_template=str(target_template) if target_template else None,
            txt_values=txt_values,
        )

    txt = None
    if "txt" in records:
        txt_section = _require_mapping(provider_id, "txt", records.get("txt"))
        required_raw = _require_mapping(
            provider_id, "txt required", txt_section.get("required", {})
        )
        required: Dict[str, List[str]] = {}
        for name, values in required_raw.items():
            values_list = _require_list(provider_id, f"txt required.{name}", values)
            required_values = [str(value) for value in values_list]
            required[str(name)] = required_values
        verification_required = txt_section.get("verification_required", False)
        if not isinstance(verification_required, bool):
            raise ValueError(
                f"Provider config {provider_id} txt verification_required must be a boolean"
            )
        txt = TXTConfig(required=required, verification_required=verification_required)

    dmarc = None
    if "dmarc" in records:
        dmarc_section = _require_mapping(provider_id, "dmarc", records.get("dmarc"))
        default_policy = dmarc_section.get("default_policy", "reject")
        default_rua_localpart = dmarc_section.get("default_rua_localpart", "postmaster")
        required_rua = _require_list(
            provider_id, "dmarc required_rua", dmarc_section.get("required_rua", [])
        )
        required_tags_raw = _require_mapping(
            provider_id, "dmarc required_tags", dmarc_section.get("required_tags", {})
        )
        required_tags = {str(key).lower(): str(value) for key, value in required_tags_raw.items()}
        dmarc = DMARCConfig(
            default_policy=str(default_policy),
            default_rua_localpart=str(default_rua_localpart),
            required_rua=[str(value) for value in required_rua],
            required_tags=required_tags,
        )

    return ProviderConfig(
        provider_id=provider_id,
        name=str(name),
        version=str(version),
        mx=mx,
        spf=spf,
        dkim=dkim,
        txt=txt,
        dmarc=dmarc,
    )


def list_providers() -> List[ProviderConfig]:
    providers: Dict[str, ProviderConfig] = {}
    for path in _iter_provider_paths():
        provider_id = Path(path.name).stem
        try:
            data = _load_yaml(path)
            if not _is_enabled(data):
                continue
            if provider_id in providers:
                continue
            providers[provider_id] = _load_provider_from_data(provider_id, data)
        except ValueError as exc:
            LOGGER.warning("Skipping provider config %s: %s", path, exc)
            continue
    return sorted(providers.values(), key=lambda item: item.provider_id)


def load_provider_config(selection: str) -> ProviderConfig:
    if not selection:
        raise ValueError("Provider selection is required")

    normalized = _normalize_key(selection)
    candidates = list_providers()
    for provider in candidates:
        if _normalize_key(provider.provider_id) == normalized:
            return provider
        if _normalize_key(provider.name) == normalized:
            return provider

    available = ", ".join(p.provider_id for p in candidates) or "none"
    raise ValueError(f"Unknown provider '{selection}'. Available: {available}")
