"""Explicit provider check CLI handler."""

from __future__ import annotations

from typing import Callable

from .shared import _build_dmarc_required_tags, _parse_txt_inputs


def handle_checks(
    args: object,
    parser: object,
    report_time: str,
    *,
    load_provider_config: Callable[[str], object],
    resolve_provider_config: Callable[..., object],
    parse_provider_vars: Callable[[list[str] | None], dict],
    parse_txt_records: Callable[[list[str] | None], dict],
    dns_checker_cls: type,
    summarize_status: Callable[[list[object]], str],
    to_json: Callable[..., str],
    to_human: Callable[..., str],
    to_text: Callable[..., str],
    logger: object,
) -> int:
    """Handle explicit provider checks.

    Args:
        args (object): Parsed CLI arguments.
        parser (object): Argument parser with an error() method.
        report_time (str): Report timestamp.
        load_provider_config (Callable[[str], object]): Provider loader callback.
        resolve_provider_config (Callable[..., object]): Provider resolver callback.
        parse_provider_vars (Callable[[list[str] | None], dict]): Variable parser callback.
        parse_txt_records (Callable[[list[str] | None], dict]): TXT parser callback.
        dns_checker_cls (type): DNSChecker class or factory.
        summarize_status (Callable[[list[object]], str]): Status summarizer.
        to_json (Callable[..., str]): JSON output formatter.
        to_human (Callable[..., str]): Human output formatter.
        to_text (Callable[..., str]): Text output formatter.
        logger (object): Logger for CLI messages.

    Returns:
        int: Exit code.
    """
    try:
        provider = load_provider_config(args.provider)
    except ValueError as exc:
        parser.error(str(exc))

    logger.info(
        "Checking %s with provider %s (v%s)",
        args.domain,
        provider.name,
        provider.version,
    )
    logger.debug(
        "Options: strict=%s output=%s spf_policy=%s skip_txt_verification=%s",
        args.strict,
        args.output,
        args.spf_policy,
        args.skip_txt_verification,
    )

    txt_records, txt_verification_records = _parse_txt_inputs(
        args,
        parser,
        parse_txt_records,
    )

    try:
        provider_vars = parse_provider_vars(args.provider_vars)
        provider = resolve_provider_config(provider, provider_vars, domain=args.domain)
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
    if args.output == "json":
        print(to_json(results, args.domain, report_time, provider.name, provider.version))
    elif args.output == "human":
        print(to_human(results, args.domain, report_time, provider.name, provider.version))
    else:
        print(to_text(results, args.domain, report_time, provider.name, provider.version))

    status = summarize_status(results)
    if status == "PASS":
        return 0
    if status == "WARN":
        return 1
    if status == "FAIL":
        return 2
    return 3
