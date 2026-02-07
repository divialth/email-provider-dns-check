"""Stable API for running DNS checks and provider detection."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from .checker import DNSChecker, RecordCheck
from .detection import DEFAULT_TOP_N, DetectionReport, detect_providers
from .detection.formatting import build_detection_payload, format_detection_report
from .dns_resolver import DnsResolver
from .output import build_json_payload, summarize_status, to_human, to_json, to_text
from .provider_config import load_provider_config, resolve_provider_config
from .status import Status, coerce_status, exit_code_for_status

LOGGER = logging.getLogger(__name__)

_OUTPUT_CHOICES = {"text", "json", "human"}


def _default_report_time() -> str:
    """Build a default UTC report timestamp string.

    Returns:
        str: Timestamp in YYYY-MM-DD HH:MM format (UTC).
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


def _validate_output_format(output: str) -> None:
    """Validate the output format selection.

    Args:
        output (str): Requested output format.

    Raises:
        ValueError: If the output format is not supported.
    """
    if output not in _OUTPUT_CHOICES:
        raise ValueError(f"Unsupported output format '{output}'. Choose from {_OUTPUT_CHOICES}.")


def _load_provider_config(
    loader: Callable[..., object], provider_id: str, provider_dirs: Optional[List[Path | str]]
) -> object:
    """Load provider config with optional provider directory support.

    Args:
        loader (Callable[..., object]): Provider loader function.
        provider_id (str): Provider identifier to load.
        provider_dirs (Optional[List[Path | str]]): Optional provider directories.

    Returns:
        object: Loaded provider configuration.
    """
    if provider_dirs:
        try:
            return loader(provider_id, provider_dirs=provider_dirs)
        except TypeError:
            return loader(provider_id)
    return loader(provider_id)


@dataclass(frozen=True)
class CheckRequest:
    """Input parameters for running provider DNS checks.

    Attributes:
        domain (str): Domain to validate.
        provider_id (str): Provider configuration ID or name.
        provider_vars (dict[str, str]): Provider variable overrides.
        provider_dirs (list[Path | str] | None): Additional provider config directories.
        strict (bool): Enforce exact provider configuration.
        dmarc_rua_mailto (Iterable[str]): Required DMARC rua mailto overrides.
        dmarc_ruf_mailto (Iterable[str]): Required DMARC ruf mailto overrides.
        dmarc_policy (Optional[str]): DMARC policy override.
        dmarc_required_tags (dict[str, str]): DMARC tag overrides.
        spf_policy (Optional[str]): SPF policy override.
        additional_spf_includes (Iterable[str]): Additional SPF include mechanisms.
        additional_spf_ip4 (Iterable[str]): Additional SPF ip4 entries.
        additional_spf_ip6 (Iterable[str]): Additional SPF ip6 entries.
        additional_txt (dict[str, list[str]]): Extra required TXT values.
        additional_txt_verification (dict[str, list[str]]): Extra TXT verification values.
        skip_txt_verification (bool): Skip provider-required TXT verification checks.
        output (str): Output format (text, json, or human).
        colorize_status (Callable[[str | Status], str] | None): Status colorizer callback.
        report_time (Optional[str]): Report timestamp (UTC).
        resolver (Optional[DnsResolver]): DNS resolver to use.
        load_provider_config_fn (Optional[Callable[..., object]]): Provider loader override.
        resolve_provider_config_fn (Optional[Callable[..., object]]): Provider resolver override.
        dns_checker_cls (Optional[type]): DNS checker class override.
        summarize_status_fn (Optional[Callable[[List[RecordCheck]], Status | str]]): Summary override.
    """

    domain: str
    provider_id: str
    provider_vars: dict[str, str] = field(default_factory=dict)
    provider_dirs: Optional[List[Path | str]] = None
    strict: bool = False
    dmarc_rua_mailto: Iterable[str] = field(default_factory=list)
    dmarc_ruf_mailto: Iterable[str] = field(default_factory=list)
    dmarc_policy: Optional[str] = None
    dmarc_required_tags: dict[str, str] = field(default_factory=dict)
    spf_policy: Optional[str] = None
    additional_spf_includes: Iterable[str] = field(default_factory=list)
    additional_spf_ip4: Iterable[str] = field(default_factory=list)
    additional_spf_ip6: Iterable[str] = field(default_factory=list)
    additional_txt: dict[str, list[str]] = field(default_factory=dict)
    additional_txt_verification: dict[str, list[str]] = field(default_factory=dict)
    skip_txt_verification: bool = False
    output: str = "human"
    colorize_status: Optional[Callable[[str | Status], str]] = None
    report_time: Optional[str] = None
    resolver: Optional[DnsResolver] = None
    load_provider_config_fn: Optional[Callable[..., object]] = None
    resolve_provider_config_fn: Optional[Callable[..., object]] = None
    dns_checker_cls: Optional[type] = None
    summarize_status_fn: Optional[Callable[[List[RecordCheck]], Status | str]] = None


@dataclass(frozen=True)
class CheckResult:
    """Output from a provider DNS check run.

    Attributes:
        output (str): Rendered output string.
        exit_code (int): Exit code derived from summary status.
        status (Status): Summary status value.
        report_time (str): Report timestamp (UTC).
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.
        results (List[RecordCheck]): Raw check results.
    """

    output: str
    exit_code: int
    status: Status
    report_time: str
    provider_name: str
    provider_version: str
    results: List[RecordCheck]


def run_checks(request: CheckRequest) -> CheckResult:
    """Run provider DNS checks using a stable API.

    Args:
        request (CheckRequest): Request parameters.

    Returns:
        CheckResult: Results including output and exit code.

    Raises:
        ValueError: If provider selection or output format is invalid.
    """
    _validate_output_format(request.output)
    report_time = request.report_time or _default_report_time()
    load_provider = request.load_provider_config_fn or load_provider_config
    resolve_provider = request.resolve_provider_config_fn or resolve_provider_config
    checker_cls = request.dns_checker_cls or DNSChecker
    summarize = request.summarize_status_fn or summarize_status

    provider = _load_provider_config(load_provider, request.provider_id, request.provider_dirs)
    provider = resolve_provider(
        provider, request.provider_vars, domain=request.domain.lower().strip()
    )

    LOGGER.info(
        "Checking %s with provider %s (v%s)",
        request.domain,
        provider.name,
        provider.version,
    )
    LOGGER.debug(
        "Options: strict=%s output=%s spf_policy=%s skip_txt_verification=%s",
        request.strict,
        request.output,
        request.spf_policy,
        request.skip_txt_verification,
    )

    resolver = request.resolver or DnsResolver()
    checker = checker_cls(
        request.domain,
        provider,
        resolver=resolver,
        strict=request.strict,
        dmarc_rua_mailto=request.dmarc_rua_mailto,
        dmarc_ruf_mailto=request.dmarc_ruf_mailto,
        dmarc_policy=request.dmarc_policy,
        dmarc_required_tags=request.dmarc_required_tags,
        spf_policy=request.spf_policy,
        additional_spf_includes=request.additional_spf_includes,
        additional_spf_ip4=request.additional_spf_ip4,
        additional_spf_ip6=request.additional_spf_ip6,
        additional_txt=request.additional_txt,
        additional_txt_verification=request.additional_txt_verification,
        skip_txt_verification=request.skip_txt_verification,
    )
    results = checker.run_checks()
    status = coerce_status(summarize(results))
    exit_code = exit_code_for_status(status)

    if request.output == "json":
        rendered = to_json(results, request.domain, report_time, provider.name, provider.version)
    elif request.output == "human":
        rendered = to_human(
            results,
            request.domain,
            report_time,
            provider.name,
            provider.version,
            colorize_status=request.colorize_status,
        )
    else:
        rendered = to_text(
            results,
            request.domain,
            report_time,
            provider.name,
            provider.version,
            colorize_status=request.colorize_status,
        )

    return CheckResult(
        output=rendered,
        exit_code=exit_code,
        status=status,
        report_time=report_time,
        provider_name=provider.name,
        provider_version=provider.version,
        results=results,
    )


@dataclass(frozen=True)
class DetectionRequest:
    """Input parameters for running provider detection.

    Attributes:
        domain (str): Domain to inspect.
        provider_dirs (list[Path | str] | None): Additional provider config directories.
        detect_limit (Optional[int]): Limit detection candidates.
        autoselect (bool): Run checks for the selected provider when unambiguous.
        strict (bool): Enforce exact provider configuration when autoselecting.
        dmarc_rua_mailto (Iterable[str]): Required DMARC rua overrides.
        dmarc_ruf_mailto (Iterable[str]): Required DMARC ruf overrides.
        dmarc_policy (Optional[str]): DMARC policy override.
        dmarc_required_tags (dict[str, str]): DMARC tag overrides.
        spf_policy (Optional[str]): SPF policy override.
        additional_spf_includes (Iterable[str]): Additional SPF include mechanisms.
        additional_spf_ip4 (Iterable[str]): Additional SPF ip4 entries.
        additional_spf_ip6 (Iterable[str]): Additional SPF ip6 entries.
        additional_txt (dict[str, list[str]]): Extra required TXT values.
        additional_txt_verification (dict[str, list[str]]): Extra TXT verification values.
        skip_txt_verification (bool): Skip provider-required TXT verification checks.
        output (str): Output format (text, json, or human).
        colorize_status (Callable[[str | Status], str] | None): Status colorizer callback.
        report_time (Optional[str]): Report timestamp (UTC).
        resolver (Optional[DnsResolver]): DNS resolver to use.
        detect_providers_fn (Optional[Callable[..., DetectionReport]]): Detection override.
        load_provider_config_fn (Optional[Callable[..., object]]): Provider loader override.
        resolve_provider_config_fn (Optional[Callable[..., object]]): Provider resolver override.
        dns_checker_cls (Optional[type]): DNS checker class override.
        summarize_status_fn (Optional[Callable[[List[RecordCheck]], Status | str]]): Summary override.
    """

    domain: str
    provider_dirs: Optional[List[Path | str]] = None
    detect_limit: Optional[int] = None
    autoselect: bool = False
    strict: bool = False
    dmarc_rua_mailto: Iterable[str] = field(default_factory=list)
    dmarc_ruf_mailto: Iterable[str] = field(default_factory=list)
    dmarc_policy: Optional[str] = None
    dmarc_required_tags: dict[str, str] = field(default_factory=dict)
    spf_policy: Optional[str] = None
    additional_spf_includes: Iterable[str] = field(default_factory=list)
    additional_spf_ip4: Iterable[str] = field(default_factory=list)
    additional_spf_ip6: Iterable[str] = field(default_factory=list)
    additional_txt: dict[str, list[str]] = field(default_factory=dict)
    additional_txt_verification: dict[str, list[str]] = field(default_factory=dict)
    skip_txt_verification: bool = False
    output: str = "human"
    colorize_status: Optional[Callable[[str | Status], str]] = None
    report_time: Optional[str] = None
    resolver: Optional[DnsResolver] = None
    detect_providers_fn: Optional[Callable[..., DetectionReport]] = None
    load_provider_config_fn: Optional[Callable[..., object]] = None
    resolve_provider_config_fn: Optional[Callable[..., object]] = None
    dns_checker_cls: Optional[type] = None
    summarize_status_fn: Optional[Callable[[List[RecordCheck]], Status | str]] = None


@dataclass(frozen=True)
class DetectionResult:
    """Output from a provider detection run.

    Attributes:
        output (str): Rendered output string.
        exit_code (int): Exit code derived from detection or check status.
        status (Status): Summary status value.
        report_time (str): Report timestamp (UTC).
        report (DetectionReport): Detection report payload.
        results (Optional[List[RecordCheck]]): Check results when autoselect ran.
    """

    output: str
    exit_code: int
    status: Status
    report_time: str
    report: DetectionReport
    results: Optional[List[RecordCheck]] = None


def run_detection(request: DetectionRequest) -> DetectionResult:
    """Run provider detection with optional autoselect checks.

    Args:
        request (DetectionRequest): Request parameters.

    Returns:
        DetectionResult: Results including output and exit code.

    Raises:
        ValueError: If the output format is invalid or provider loading fails.
    """
    _validate_output_format(request.output)
    report_time = request.report_time or _default_report_time()
    normalized_domain = request.domain.lower().strip()
    resolver = request.resolver or DnsResolver()
    detect = request.detect_providers_fn or detect_providers
    load_provider = request.load_provider_config_fn or load_provider_config
    resolve_provider = request.resolve_provider_config_fn or resolve_provider_config
    checker_cls = request.dns_checker_cls or DNSChecker
    summarize = request.summarize_status_fn or summarize_status

    top_n = request.detect_limit if request.detect_limit is not None else DEFAULT_TOP_N
    detect_kwargs = {"resolver": resolver, "top_n": top_n}
    if request.provider_dirs:
        detect_kwargs["provider_dirs"] = request.provider_dirs
    report = detect(normalized_domain, **detect_kwargs)
    status = report.status
    results: Optional[List[RecordCheck]] = None

    if request.output == "json":
        detection_payload = build_detection_payload(report, report_time)
        if request.autoselect and report.selected and not report.ambiguous:
            provider = _load_provider_config(
                load_provider, report.selected.provider_id, request.provider_dirs
            )
            provider = resolve_provider(
                provider, report.selected.inferred_variables, domain=normalized_domain
            )
            checker = checker_cls(
                request.domain,
                provider,
                resolver=resolver,
                strict=request.strict,
                dmarc_rua_mailto=request.dmarc_rua_mailto,
                dmarc_ruf_mailto=request.dmarc_ruf_mailto,
                dmarc_policy=request.dmarc_policy,
                dmarc_required_tags=request.dmarc_required_tags,
                spf_policy=request.spf_policy,
                additional_spf_includes=request.additional_spf_includes,
                additional_spf_ip4=request.additional_spf_ip4,
                additional_spf_ip6=request.additional_spf_ip6,
                additional_txt=request.additional_txt,
                additional_txt_verification=request.additional_txt_verification,
                skip_txt_verification=request.skip_txt_verification,
            )
            results = checker.run_checks()
            detection_payload["report"] = build_json_payload(
                results, request.domain, report_time, provider.name, provider.version
            )
            status = coerce_status(summarize(results))
            exit_code = exit_code_for_status(status)
        else:
            exit_code = (
                exit_code_for_status(Status.PASS)
                if report.status is Status.PASS and not report.ambiguous
                else exit_code_for_status(Status.UNKNOWN)
            )
        rendered = json.dumps(detection_payload, indent=2)
        return DetectionResult(
            output=rendered,
            exit_code=exit_code,
            status=status,
            report_time=report_time,
            report=report,
            results=results,
        )

    detection_output = format_detection_report(
        report, report_time, colorize_status=request.colorize_status
    )
    if request.autoselect and report.selected and not report.ambiguous:
        provider = _load_provider_config(
            load_provider, report.selected.provider_id, request.provider_dirs
        )
        provider = resolve_provider(
            provider, report.selected.inferred_variables, domain=normalized_domain
        )
        checker = checker_cls(
            request.domain,
            provider,
            resolver=resolver,
            strict=request.strict,
            dmarc_rua_mailto=request.dmarc_rua_mailto,
            dmarc_ruf_mailto=request.dmarc_ruf_mailto,
            dmarc_policy=request.dmarc_policy,
            dmarc_required_tags=request.dmarc_required_tags,
            spf_policy=request.spf_policy,
            additional_spf_includes=request.additional_spf_includes,
            additional_spf_ip4=request.additional_spf_ip4,
            additional_spf_ip6=request.additional_spf_ip6,
            additional_txt=request.additional_txt,
            additional_txt_verification=request.additional_txt_verification,
            skip_txt_verification=request.skip_txt_verification,
        )
        results = checker.run_checks()
        status = coerce_status(summarize(results))
        exit_code = exit_code_for_status(status)
        if request.output == "human":
            check_output = to_human(
                results,
                request.domain,
                report_time,
                provider.name,
                provider.version,
                colorize_status=request.colorize_status,
            )
        else:
            check_output = to_text(
                results,
                request.domain,
                report_time,
                provider.name,
                provider.version,
                colorize_status=request.colorize_status,
            )
        rendered = f"{detection_output}\n\n{check_output}"
    else:
        exit_code = (
            exit_code_for_status(Status.PASS)
            if report.status is Status.PASS and not report.ambiguous
            else exit_code_for_status(Status.UNKNOWN)
        )
        rendered = detection_output

    return DetectionResult(
        output=rendered,
        exit_code=exit_code,
        status=status,
        report_time=report_time,
        report=report,
        results=results,
    )
