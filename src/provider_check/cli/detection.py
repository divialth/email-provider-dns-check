"""Provider detection CLI handler."""

from __future__ import annotations

from typing import Callable, Optional

from ..dns_resolver import DnsResolver
from ..runner import DetectionRequest, run_detection

from .shared import _build_dmarc_required_tags, _parse_txt_inputs


def handle_detection(
    args: object,
    parser: object,
    report_time: str,
    *,
    resolver: DnsResolver,
    parse_txt_records: Callable[[list[str] | None], dict],
    colorize_status: Callable[[str], str],
    provider_dirs: Optional[list[object]] = None,
    detect_providers: Optional[Callable[..., object]] = None,
    load_provider_config: Optional[Callable[..., object]] = None,
    resolve_provider_config: Optional[Callable[..., object]] = None,
    dns_checker_cls: Optional[type] = None,
    summarize_status: Optional[Callable[[list[object]], str]] = None,
) -> int:
    """Handle provider detection and autoselect flows.

    Args:
        args (object): Parsed CLI arguments.
        parser (object): Argument parser with an error() method.
        report_time (str): Report timestamp.
        resolver (DnsResolver): DNS resolver to use for lookups.
        parse_txt_records (Callable[[list[str] | None], dict]): TXT parser callback.
        colorize_status (Callable[[str], str]): Status colorizer callback.
        provider_dirs (Optional[list[object]]): Additional provider config directories.
        detect_providers (Optional[Callable[..., object]]): Detection override.
        load_provider_config (Optional[Callable[..., object]]): Provider loader override.
        resolve_provider_config (Optional[Callable[..., object]]): Provider resolver override.
        dns_checker_cls (Optional[type]): DNS checker class override.
        summarize_status (Optional[Callable[[list[object]], str]]): Status override.

    Returns:
        int: Exit code.
    """
    txt_records, txt_verification_records = _parse_txt_inputs(
        args,
        parser,
        parse_txt_records,
    )
    try:
        result = run_detection(
            DetectionRequest(
                domain=args.domain,
                provider_dirs=provider_dirs,
                detect_limit=args.provider_detect_limit,
                autoselect=args.provider_autoselect,
                strict=args.strict,
                dmarc_rua_mailto=args.dmarc_rua_mailto,
                dmarc_ruf_mailto=args.dmarc_ruf_mailto,
                dmarc_policy=args.dmarc_policy,
                dmarc_required_tags=_build_dmarc_required_tags(args),
                spf_policy=args.spf_policy,
                additional_spf_includes=args.spf_includes,
                additional_spf_ip4=args.spf_ip4,
                additional_spf_ip6=args.spf_ip6,
                additional_txt=txt_records,
                additional_txt_verification=txt_verification_records,
                skip_txt_verification=args.skip_txt_verification,
                output=args.output,
                colorize_status=colorize_status,
                report_time=report_time,
                resolver=resolver,
                detect_providers_fn=detect_providers,
                load_provider_config_fn=load_provider_config,
                resolve_provider_config_fn=resolve_provider_config,
                dns_checker_cls=dns_checker_cls,
                summarize_status_fn=summarize_status,
            )
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(result.output)
    return result.exit_code
