"""Provider detection CLI handler."""

from __future__ import annotations

import json
from typing import Callable

from .shared import _build_dmarc_required_tags


def handle_detection(
    args: object,
    parser: object,
    report_time: str,
    *,
    detect_providers: Callable[..., object],
    default_top_n: int,
    format_detection_report: Callable[[object, str], str],
    build_detection_payload: Callable[[object, str], dict],
    load_provider_config: Callable[[str], object],
    resolve_provider_config: Callable[..., object],
    parse_txt_records: Callable[[list[str] | None], dict],
    dns_checker_cls: type,
    build_json_payload: Callable[..., dict],
    summarize_status: Callable[[list[object]], str],
    to_human: Callable[..., str],
    to_text: Callable[..., str],
) -> int:
    """Handle provider detection and autoselect flows.

    Args:
        args (object): Parsed CLI arguments.
        parser (object): Argument parser with an error() method.
        report_time (str): Report timestamp.
        detect_providers (Callable[..., object]): Provider detection callback.
        default_top_n (int): Default number of candidates to return.
        format_detection_report (Callable[[object, str], str]): Report formatter.
        build_detection_payload (Callable[[object, str], dict]): JSON payload builder.
        load_provider_config (Callable[[str], object]): Provider loader callback.
        resolve_provider_config (Callable[..., object]): Provider resolver callback.
        parse_txt_records (Callable[[list[str] | None], dict]): TXT parser callback.
        dns_checker_cls (type): DNSChecker class or factory.
        build_json_payload (Callable[..., dict]): JSON payload builder.
        summarize_status (Callable[[list[object]], str]): Status summarizer.
        to_human (Callable[..., str]): Human output formatter.
        to_text (Callable[..., str]): Text output formatter.

    Returns:
        int: Exit code.
    """
    report = detect_providers(args.domain, top_n=default_top_n)
    detection_output = format_detection_report(report, report_time)
    if args.output == "json":
        detection_payload = build_detection_payload(report, report_time)
        if args.provider_autoselect and report.selected and not report.ambiguous:
            try:
                provider = load_provider_config(report.selected.provider_id)
            except ValueError as exc:
                parser.error(str(exc))
            provider = resolve_provider_config(
                provider, report.selected.inferred_variables, domain=args.domain
            )
            try:
                txt_records = parse_txt_records(args.txt_records)
                txt_verification_records = parse_txt_records(args.txt_verification_records)
            except ValueError as exc:
                parser.error(str(exc))
            checker = dns_checker_cls(
                args.domain,
                provider,
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
            )
            results = checker.run_checks()
            detection_payload["report"] = build_json_payload(
                results, args.domain, report_time, provider.name, provider.version
            )
            print(json.dumps(detection_payload, indent=2))
            status = summarize_status(results)
            if status == "PASS":
                return 0
            if status == "WARN":
                return 1
            if status == "FAIL":
                return 2
            return 3
        print(json.dumps(detection_payload, indent=2))
        return 0 if report.status == "PASS" and not report.ambiguous else 3

    print(detection_output)
    if args.provider_autoselect and report.selected and not report.ambiguous:
        try:
            provider = load_provider_config(report.selected.provider_id)
        except ValueError as exc:
            parser.error(str(exc))
        provider = resolve_provider_config(
            provider, report.selected.inferred_variables, domain=args.domain
        )
        try:
            txt_records = parse_txt_records(args.txt_records)
            txt_verification_records = parse_txt_records(args.txt_verification_records)
        except ValueError as exc:
            parser.error(str(exc))

        checker = dns_checker_cls(
            args.domain,
            provider,
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
        )
        results = checker.run_checks()
        if args.output == "human":
            print()
            print(to_human(results, args.domain, report_time, provider.name, provider.version))
        else:
            print()
            print(to_text(results, args.domain, report_time, provider.name, provider.version))

        status = summarize_status(results)
        if status == "PASS":
            return 0
        if status == "WARN":
            return 1
        if status == "FAIL":
            return 2
        return 3

    return 0 if report.status == "PASS" and not report.ambiguous else 3
