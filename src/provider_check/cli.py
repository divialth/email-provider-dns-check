"""Command-line interface for the DNS checker."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import List

import yaml

from . import __version__
from .checker import DNSChecker
from .detection import DEFAULT_TOP_N, DetectionReport, detect_providers
from .output import build_json_payload, summarize_status, to_human, to_json, to_text
from .provider_config import (
    list_providers,
    load_provider_config,
    load_provider_config_data,
    resolve_provider_config,
)

LOGGER = logging.getLogger(__name__)


class _LiteralString(str):
    """Marker type for YAML literal block rendering."""

    pass


class _ProviderShowDumper(yaml.SafeDumper):
    """YAML dumper configured for provider show output."""

    pass


def _literal_string_representer(dumper: yaml.Dumper, value: _LiteralString) -> yaml.ScalarNode:
    """Represent a string using YAML literal block style.

    Args:
        dumper (yaml.Dumper): YAML dumper instance.
        value (_LiteralString): Value to represent.

    Returns:
        yaml.ScalarNode: YAML scalar node with literal style.
    """
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")


_ProviderShowDumper.add_representer(_LiteralString, _literal_string_representer)


def _strip_long_description_indicator(rendered: str) -> str:
    """Normalize long_description formatting for YAML output.

    Args:
        rendered (str): YAML content rendered by PyYAML.

    Returns:
        str: Updated YAML with a clean long_description indicator.
    """
    lines = rendered.splitlines()
    updated = False
    for idx, line in enumerate(lines):
        if not line.startswith("long_description:"):
            continue
        remainder = line[len("long_description:") :].lstrip()
        if remainder.startswith("|"):
            lines[idx] = "long_description:"
            updated = True
            break
    if not updated:
        return rendered
    suffix = "\n" if rendered.endswith("\n") else ""
    return "\n".join(lines) + suffix


def _build_detection_payload(report: DetectionReport, report_time: str) -> dict:
    """Build a JSON-serializable payload from a detection report.

    Args:
        report (DetectionReport): Detection report data.
        report_time (str): UTC report timestamp string.

    Returns:
        dict: JSON-serializable payload.
    """
    candidates = []
    for candidate in report.candidates:
        candidates.append(
            {
                "provider_id": candidate.provider_id,
                "provider_name": candidate.provider_name,
                "provider_version": candidate.provider_version,
                "score": candidate.score,
                "max_score": candidate.max_score,
                "score_ratio": round(candidate.score_ratio, 4),
                "optional_bonus": candidate.optional_bonus,
                "status_counts": dict(candidate.status_counts),
                "record_statuses": dict(candidate.record_statuses),
                "core_pass_records": list(candidate.core_pass_records),
                "inferred_variables": dict(candidate.inferred_variables),
            }
        )
    selected_provider = None
    if report.selected:
        selected_provider = {
            "provider_id": report.selected.provider_id,
            "provider_name": report.selected.provider_name,
            "provider_version": report.selected.provider_version,
        }
    return {
        "domain": report.domain,
        "report_time_utc": report_time,
        "status": report.status,
        "top_n": report.top_n,
        "ambiguous": report.ambiguous,
        "selected_provider": selected_provider,
        "candidates": candidates,
    }


def _format_detection_report(report: DetectionReport, report_time: str) -> str:
    """Format a detection report as human-readable text.

    Args:
        report (DetectionReport): Detection report data.
        report_time (str): UTC report timestamp string.

    Returns:
        str: Formatted detection report.
    """
    lines = [
        f"{report.status} - provider detection report for domain {report.domain} ({report_time})"
    ]
    if report.selected:
        lines.append(
            "Selected provider: "
            f"{report.selected.provider_id} ({report.selected.provider_name} "
            f"v{report.selected.provider_version})"
        )
    elif report.ambiguous:
        lines.append("Top candidates are tied; unable to select provider.")
    else:
        lines.append("No matching providers detected.")

    if report.candidates:
        lines.append(f"Top {len(report.candidates)} candidates:")
        for idx, candidate in enumerate(report.candidates, start=1):
            if candidate.max_score:
                score_label = (
                    f"{candidate.score}/{candidate.max_score} ({candidate.score_ratio:.0%})"
                )
            else:
                score_label = "n/a"
            lines.append(
                f"{idx}. {candidate.provider_id} - {candidate.provider_name} "
                f"(v{candidate.provider_version}) score {score_label}"
            )
            details: List[str] = []
            if candidate.core_pass_records:
                details.append(f"core: {', '.join(candidate.core_pass_records)}")
            if candidate.record_statuses:
                record_summary = " ".join(
                    f"{key}={value}" for key, value in sorted(candidate.record_statuses.items())
                )
                details.append(f"records: {record_summary}")
            if candidate.optional_bonus:
                details.append(f"optional bonus: {candidate.optional_bonus}")
            if candidate.inferred_variables:
                vars_summary = ", ".join(
                    f"{key}={value}" for key, value in sorted(candidate.inferred_variables.items())
                )
                details.append(f"vars: {vars_summary}")
            if details:
                lines.append(f"  {' | '.join(details)}")
    return "\n".join(lines)


def _setup_logging(verbosity: int) -> None:
    """Configure logging based on verbosity level.

    Args:
        verbosity (int): Verbosity count from CLI flags.
    """
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.Formatter.converter = time.gmtime  # UTC timestamps
    logging.basicConfig(
        level=level,
        format="%(asctime)sZ [%(levelname)s] %(name)s: %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        argparse.ArgumentParser: Configured parser instance.
    """
    parser = argparse.ArgumentParser(
        description="Check email provider DNS records for a given domain",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target_group = parser.add_argument_group("Target")
    provider_group = parser.add_argument_group("Provider selection")
    output_group = parser.add_argument_group("Output")
    validation_group = parser.add_argument_group("Validation options")
    dmarc_group = parser.add_argument_group("Validation options DMARC")
    spf_group = parser.add_argument_group("SPF options")
    txt_group = parser.add_argument_group("TXT options")
    logging_group = parser.add_argument_group("Logging")
    misc_group = parser.add_argument_group("Misc")

    target_group.add_argument("domain", nargs="?", help="Domain to validate")
    provider_group.add_argument(
        "--provider",
        help="Provider configuration to use (see --providers-list)",
    )
    provider_group.add_argument(
        "--provider-detect",
        dest="provider_detect",
        action="store_true",
        help="Detect the closest matching provider and exit",
    )
    provider_group.add_argument(
        "--provider-autoselect",
        dest="provider_autoselect",
        action="store_true",
        help="Detect the closest matching provider and run checks",
    )
    provider_group.add_argument(
        "--providers-list",
        dest="providers_list",
        action="store_true",
        help="List available providers and exit",
    )
    provider_group.add_argument(
        "--list-providers",
        dest="providers_list",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    provider_group.add_argument(
        "--provider-show",
        dest="provider_show",
        metavar="PROVIDER",
        help="Show provider configuration and exit",
    )
    provider_group.add_argument(
        "--provider-var",
        dest="provider_vars",
        action="append",
        default=[],
        help="Provider variables in name=value form (repeatable)",
    )
    misc_group.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit",
    )
    output_group.add_argument(
        "--output",
        choices=["text", "json", "human"],
        default="human",
        help="Output format",
    )
    validation_group.add_argument(
        "--strict",
        action="store_true",
        help="Enforce exact provider configuration (no extras allowed)",
    )
    dmarc_group.add_argument(
        "--dmarc-rua-mailto",
        dest="dmarc_rua_mailto",
        action="append",
        default=[],
        help="DMARC rua mailto URI to require (repeatable; mailto: prefix optional)",
    )
    dmarc_group.add_argument(
        "--dmarc-ruf-mailto",
        dest="dmarc_ruf_mailto",
        action="append",
        default=[],
        help="DMARC ruf mailto URI to require (repeatable; mailto: prefix optional)",
    )
    dmarc_group.add_argument(
        "--dmarc-policy",
        dest="dmarc_policy",
        choices=["none", "quarantine", "reject"],
        default=None,
        help="DMARC policy (p=). Defaults to provider config.",
    )
    dmarc_group.add_argument(
        "--dmarc-subdomain-policy",
        dest="dmarc_subdomain_policy",
        choices=["none", "quarantine", "reject"],
        default=None,
        help="DMARC subdomain policy (sp=). Overrides provider defaults.",
    )
    dmarc_group.add_argument(
        "--dmarc-adkim",
        dest="dmarc_adkim",
        choices=["r", "s"],
        default=None,
        help="DMARC DKIM alignment mode (adkim=). Overrides provider defaults.",
    )
    dmarc_group.add_argument(
        "--dmarc-aspf",
        dest="dmarc_aspf",
        choices=["r", "s"],
        default=None,
        help="DMARC SPF alignment mode (aspf=). Overrides provider defaults.",
    )
    dmarc_group.add_argument(
        "--dmarc-pct",
        dest="dmarc_pct",
        type=_parse_dmarc_pct,
        default=None,
        help="DMARC enforcement percentage (pct=). Overrides provider defaults.",
    )
    spf_group.add_argument(
        "--spf-policy",
        dest="spf_policy",
        choices=["softfail", "hardfail"],
        default="hardfail",
        help="SPF policy: softfail (~all) or hardfail (-all)",
    )
    spf_group.add_argument(
        "--spf-include",
        dest="spf_includes",
        action="append",
        default=[],
        help="Additional SPF include mechanisms",
    )
    spf_group.add_argument(
        "--spf-ip4",
        dest="spf_ip4",
        action="append",
        default=[],
        help="Additional SPF ip4 mechanisms",
    )
    spf_group.add_argument(
        "--spf-ip6",
        dest="spf_ip6",
        action="append",
        default=[],
        help="Additional SPF ip6 mechanisms",
    )
    txt_group.add_argument(
        "--txt",
        dest="txt_records",
        action="append",
        default=[],
        help="Require TXT record in the form name=value (repeatable)",
    )
    txt_group.add_argument(
        "--txt-verification",
        dest="txt_verification_records",
        action="append",
        default=[],
        help="Require TXT verification record in the form name=value (repeatable)",
    )
    txt_group.add_argument(
        "--skip-txt-verification",
        action="store_true",
        help="Skip provider-required TXT verification checks",
    )
    logging_group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (use -vv for debug)",
    )
    return parser


def _parse_txt_records(raw_records: List[str]) -> dict[str, list[str]]:
    """Parse TXT record requirements from CLI values.

    Args:
        raw_records (List[str]): Values in name=value form.

    Returns:
        dict[str, list[str]]: Parsed TXT values by name.

    Raises:
        ValueError: If any value is missing a name or value.
    """
    required: dict[str, list[str]] = {}
    for item in raw_records:
        if "=" not in item:
            raise ValueError(f"TXT record '{item}' must be in name=value form")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"TXT record '{item}' must include both name and value")
        required.setdefault(name, []).append(value)
    return required


def _parse_dmarc_pct(value: str) -> int:
    """Parse a DMARC pct value from CLI input.

    Args:
        value (str): String value to parse.

    Returns:
        int: Parsed percentage between 0 and 100.

    Raises:
        argparse.ArgumentTypeError: If the value is invalid or out of range.
    """
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("DMARC pct must be an integer between 0 and 100") from exc
    if parsed < 0 or parsed > 100:
        raise argparse.ArgumentTypeError("DMARC pct must be between 0 and 100")
    return parsed


def _parse_provider_vars(raw_vars: List[str]) -> dict[str, str]:
    """Parse provider variables from CLI values.

    Args:
        raw_vars (List[str]): Values in name=value form.

    Returns:
        dict[str, str]: Parsed variables mapping.

    Raises:
        ValueError: If any variable is malformed or duplicated.
    """
    parsed: dict[str, str] = {}
    for item in raw_vars:
        if "=" not in item:
            raise ValueError(f"Provider variable '{item}' must be in name=value form")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise ValueError(f"Provider variable '{item}' must include both name and value")
        if name in parsed:
            raise ValueError(f"Provider variable '{name}' was provided more than once")
        parsed[name] = value
    return parsed


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
