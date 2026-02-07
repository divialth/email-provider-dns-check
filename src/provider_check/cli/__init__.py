"""Command-line interface for the DNS checker."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from ..checker import DNSChecker
from ..detection import detect_providers
from ..dns_resolver import DnsResolver
from ..output import make_status_colorizer, resolve_color_enabled, summarize_status
from ..provider_config import (
    list_providers,
    load_provider_config,
    load_provider_config_data,
    resolve_provider_config,
)
from .checks import handle_checks
from .detection import handle_detection
from .formatting import _build_detection_payload, _format_detection_report
from .parser import _setup_logging, build_parser
from .parsing import (
    _parse_dmarc_pct,
    _parse_positive_float,
    _parse_positive_int,
    _parse_provider_vars,
    _parse_txt_records,
)
from .providers import handle_provider_show, handle_providers_list, handle_providers_validate
from .yaml_format import _LiteralString, _ProviderShowDumper, _strip_long_description_indicator

LOGGER = logging.getLogger(__name__)

__all__ = [
    "_build_detection_payload",
    "_format_detection_report",
    "_parse_dmarc_pct",
    "_parse_positive_float",
    "_parse_positive_int",
    "_parse_provider_vars",
    "_parse_txt_records",
    "_setup_logging",
    "_strip_long_description_indicator",
    "build_parser",
    "main",
]


def main(argv: List[str] | None = None) -> int:
    """Run the CLI entrypoint.

    Args:
        argv (List[str] | None): Optional argument list for parsing.

    Returns:
        int: Exit code (0=PASS, 1=WARN, 2=FAIL, 3=UNKNOWN/ambiguous).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)
    LOGGER.debug("Parsed arguments: %s", args)
    color_enabled = resolve_color_enabled(args.color, sys.stdout)
    colorize_status = make_status_colorizer(color_enabled)

    domain = args.domain
    if args.domain_flag:
        if args.domain:
            parser.error("domain may be provided either as positional or via --domain")
        domain = args.domain_flag
    args.domain = domain

    provider_dirs: list[Path] = []
    for entry in args.providers_dirs:
        path = Path(entry).expanduser()
        if path not in provider_dirs:
            provider_dirs.append(path)

    load_provider_config_data_fn = load_provider_config_data
    if provider_dirs:
        load_provider_config_data_fn = lambda selection: load_provider_config_data(
            selection, provider_dirs=provider_dirs
        )
        list_providers_fn = lambda: list_providers(provider_dirs=provider_dirs)
    else:
        list_providers_fn = list_providers

    if args.providers_list:
        LOGGER.info("Listing available providers")
        return handle_providers_list(list_providers_fn)

    if args.providers_validate:
        if args.provider_show:
            parser.error("--providers-validate cannot be combined with --provider-show")
        if args.provider:
            parser.error("--providers-validate cannot be combined with --provider")
        if args.provider_detect or args.provider_autoselect:
            parser.error(
                "--providers-validate cannot be combined with --provider-detect or "
                "--provider-autoselect"
            )
        LOGGER.info("Validating external/custom provider YAML files")
        return handle_providers_validate(provider_dirs)

    if args.provider_show:
        LOGGER.info("Showing provider configuration for %s", args.provider_show)
        return handle_provider_show(
            args.provider_show,
            parser,
            load_provider_config_data=load_provider_config_data_fn,
            literal_string_cls=_LiteralString,
            provider_show_dumper=_ProviderShowDumper,
            strip_long_description_indicator=_strip_long_description_indicator,
        )

    if not args.domain:
        parser.error(
            "domain is required unless --providers-list or --provider-show is used "
            "(use positional or --domain)"
        )

    if args.provider_detect and args.provider_autoselect:
        parser.error("--provider-detect and --provider-autoselect are mutually exclusive")

    if args.provider and (args.provider_detect or args.provider_autoselect):
        parser.error("--provider cannot be used with --provider-detect or --provider-autoselect")

    if args.provider_vars and (args.provider_detect or args.provider_autoselect):
        parser.error(
            "--provider-var is not supported with --provider-detect or --provider-autoselect"
        )

    if args.provider_detect_limit is not None and not (
        args.provider_detect or args.provider_autoselect
    ):
        parser.error("--provider-detect-limit requires --provider-detect or --provider-autoselect")

    try:
        resolver = DnsResolver(
            nameservers=args.dns_servers,
            timeout=args.dns_timeout,
            lifetime=args.dns_lifetime,
            use_tcp=args.dns_tcp,
        )
    except ValueError as exc:
        parser.error(str(exc))

    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    if args.provider_detect or args.provider_autoselect:
        return handle_detection(
            args,
            parser,
            report_time,
            resolver=resolver,
            parse_txt_records=_parse_txt_records,
            colorize_status=colorize_status,
            provider_dirs=provider_dirs,
            detect_providers=detect_providers,
            load_provider_config=load_provider_config,
            resolve_provider_config=resolve_provider_config,
            dns_checker_cls=DNSChecker,
            summarize_status=summarize_status,
        )

    if not args.provider:
        parser.error("--provider is required unless --providers-list or --provider-show is used")

    return handle_checks(
        args,
        parser,
        report_time,
        resolver=resolver,
        parse_provider_vars=_parse_provider_vars,
        parse_txt_records=_parse_txt_records,
        logger=LOGGER,
        colorize_status=colorize_status,
        provider_dirs=provider_dirs,
        load_provider_config=load_provider_config,
        resolve_provider_config=resolve_provider_config,
        dns_checker_cls=DNSChecker,
        summarize_status=summarize_status,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
