"""Command-line interface for the DNS checker."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import List

import yaml

from ..checker import DNSChecker
from ..detection import DEFAULT_TOP_N, detect_providers
from ..output import build_json_payload, summarize_status, to_human, to_json, to_text
from ..provider_config import (
    list_providers,
    load_provider_config,
    load_provider_config_data,
    resolve_provider_config,
)
from .formatting import _build_detection_payload, _format_detection_report
from .parser import _setup_logging, build_parser
from .parsing import _parse_dmarc_pct, _parse_provider_vars, _parse_txt_records
from .yaml_format import _LiteralString, _ProviderShowDumper, _strip_long_description_indicator

LOGGER = logging.getLogger(__name__)

__all__ = [
    "_build_detection_payload",
    "_format_detection_report",
    "_parse_dmarc_pct",
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

    if args.providers_list:
        LOGGER.info("Listing available providers")
        providers = list_providers()
        min_id_width = 24
        min_version_width = 6
        if providers:
            id_width = max(min_id_width, max(len(provider.provider_id) for provider in providers))
            version_width = max(
                min_version_width,
                max(len(f"v{provider.version}") for provider in providers),
            )
        else:
            id_width = min_id_width
            version_width = min_version_width
        for provider in providers:
            version_label = f"v{provider.version}"
            print(
                f"{provider.provider_id.ljust(id_width)}  "
                f"{version_label.ljust(version_width)}  {provider.name}"
            )
        return 0

    if args.provider_show:
        LOGGER.info("Showing provider configuration for %s", args.provider_show)
        try:
            _, data = load_provider_config_data(args.provider_show)
        except ValueError as exc:
            parser.error(str(exc))
        if isinstance(data.get("long_description"), str):
            data = dict(data)
            data["long_description"] = _LiteralString(data["long_description"])
        rendered = yaml.dump(
            data,
            Dumper=_ProviderShowDumper,
            sort_keys=False,
            width=10**9,
            default_flow_style=False,
        )
        print(_strip_long_description_indicator(rendered))
        return 0

    if not args.domain:
        parser.error("domain is required unless --providers-list or --provider-show is used")

    if args.provider_detect and args.provider_autoselect:
        parser.error("--provider-detect and --provider-autoselect are mutually exclusive")

    if args.provider and (args.provider_detect or args.provider_autoselect):
        parser.error("--provider cannot be used with --provider-detect or --provider-autoselect")

    if args.provider_vars and (args.provider_detect or args.provider_autoselect):
        parser.error(
            "--provider-var is not supported with --provider-detect or --provider-autoselect"
        )

    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    if args.provider_detect or args.provider_autoselect:
        report = detect_providers(args.domain, top_n=DEFAULT_TOP_N)
        detection_output = _format_detection_report(report, report_time)
        if args.output == "json":
            detection_payload = _build_detection_payload(report, report_time)
            if args.provider_autoselect and report.selected and not report.ambiguous:
                try:
                    provider = load_provider_config(report.selected.provider_id)
                except ValueError as exc:
                    parser.error(str(exc))
                provider = resolve_provider_config(
                    provider, report.selected.inferred_variables, domain=args.domain
                )
                try:
                    txt_records = _parse_txt_records(args.txt_records)
                    txt_verification_records = _parse_txt_records(args.txt_verification_records)
                except ValueError as exc:
                    parser.error(str(exc))
                dmarc_required_tags = {}
                if args.dmarc_subdomain_policy:
                    dmarc_required_tags["sp"] = args.dmarc_subdomain_policy
                if args.dmarc_adkim:
                    dmarc_required_tags["adkim"] = args.dmarc_adkim
                if args.dmarc_aspf:
                    dmarc_required_tags["aspf"] = args.dmarc_aspf
                if args.dmarc_pct is not None:
                    dmarc_required_tags["pct"] = str(args.dmarc_pct)
                checker = DNSChecker(
                    args.domain,
                    provider,
                    strict=args.strict,
                    dmarc_rua_mailto=args.dmarc_rua_mailto,
                    dmarc_ruf_mailto=args.dmarc_ruf_mailto,
                    dmarc_policy=args.dmarc_policy,
                    dmarc_required_tags=dmarc_required_tags,
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
                txt_records = _parse_txt_records(args.txt_records)
                txt_verification_records = _parse_txt_records(args.txt_verification_records)
            except ValueError as exc:
                parser.error(str(exc))

            dmarc_required_tags = {}
            if args.dmarc_subdomain_policy:
                dmarc_required_tags["sp"] = args.dmarc_subdomain_policy
            if args.dmarc_adkim:
                dmarc_required_tags["adkim"] = args.dmarc_adkim
            if args.dmarc_aspf:
                dmarc_required_tags["aspf"] = args.dmarc_aspf
            if args.dmarc_pct is not None:
                dmarc_required_tags["pct"] = str(args.dmarc_pct)

            checker = DNSChecker(
                args.domain,
                provider,
                strict=args.strict,
                dmarc_rua_mailto=args.dmarc_rua_mailto,
                dmarc_ruf_mailto=args.dmarc_ruf_mailto,
                dmarc_policy=args.dmarc_policy,
                dmarc_required_tags=dmarc_required_tags,
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

    if not args.provider:
        parser.error("--provider is required unless --providers-list or --provider-show is used")

    try:
        provider = load_provider_config(args.provider)
    except ValueError as exc:
        parser.error(str(exc))

    LOGGER.info(
        "Checking %s with provider %s (v%s)",
        args.domain,
        provider.name,
        provider.version,
    )
    LOGGER.debug(
        "Options: strict=%s output=%s spf_policy=%s skip_txt_verification=%s",
        args.strict,
        args.output,
        args.spf_policy,
        args.skip_txt_verification,
    )

    try:
        txt_records = _parse_txt_records(args.txt_records)
        txt_verification_records = _parse_txt_records(args.txt_verification_records)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        provider_vars = _parse_provider_vars(args.provider_vars)
        provider = resolve_provider_config(provider, provider_vars, domain=args.domain)
    except ValueError as exc:
        parser.error(str(exc))

    dmarc_required_tags = {}
    if args.dmarc_subdomain_policy:
        dmarc_required_tags["sp"] = args.dmarc_subdomain_policy
    if args.dmarc_adkim:
        dmarc_required_tags["adkim"] = args.dmarc_adkim
    if args.dmarc_aspf:
        dmarc_required_tags["aspf"] = args.dmarc_aspf
    if args.dmarc_pct is not None:
        dmarc_required_tags["pct"] = str(args.dmarc_pct)

    checker = DNSChecker(
        args.domain,
        provider,
        strict=args.strict,
        dmarc_rua_mailto=args.dmarc_rua_mailto,
        dmarc_ruf_mailto=args.dmarc_ruf_mailto,
        dmarc_policy=args.dmarc_policy,
        dmarc_required_tags=dmarc_required_tags,
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


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
