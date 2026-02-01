"""Command-line interface for the DNS checker."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from typing import List

import yaml

from . import __version__
from .checker import DNSChecker
from .output import summarize_status, to_human, to_json, to_text
from .provider_config import (
    list_providers,
    load_provider_config,
    load_provider_config_data,
    resolve_provider_config,
)


class _LiteralString(str):
    pass


class _ProviderShowDumper(yaml.SafeDumper):
    pass


def _literal_string_representer(dumper: yaml.Dumper, value: _LiteralString) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")


_ProviderShowDumper.add_representer(_LiteralString, _literal_string_representer)


def _strip_long_description_indicator(rendered: str) -> str:
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


def _setup_logging(verbosity: int) -> None:
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
    parser = argparse.ArgumentParser(
        description="Check email provider DNS records for a given domain",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target_group = parser.add_argument_group("Target")
    provider_group = parser.add_argument_group("Provider selection")
    output_group = parser.add_argument_group("Output")
    validation_group = parser.add_argument_group("Validation options")
    logging_group = parser.add_argument_group("Logging")
    misc_group = parser.add_argument_group("Misc")

    target_group.add_argument("domain", nargs="?", help="Domain to validate")
    provider_group.add_argument(
        "--provider",
        help="Provider configuration to use (see --providers-list)",
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
    validation_group.add_argument(
        "--dmarc-rua-mailto",
        dest="dmarc_rua_mailto",
        action="append",
        default=[],
        help="DMARC rua mailto URI to require (repeatable; mailto: prefix optional)",
    )
    validation_group.add_argument(
        "--dmarc-ruf-mailto",
        dest="dmarc_ruf_mailto",
        action="append",
        default=[],
        help="DMARC ruf mailto URI to require (repeatable; mailto: prefix optional)",
    )
    validation_group.add_argument(
        "--dmarc-policy",
        dest="dmarc_policy",
        choices=["none", "quarantine", "reject"],
        default=None,
        help="DMARC policy (p=). Defaults to provider config.",
    )
    validation_group.add_argument(
        "--spf-policy",
        dest="spf_policy",
        choices=["softfail", "hardfail"],
        default="hardfail",
        help="SPF policy: softfail (~all) or hardfail (-all)",
    )
    validation_group.add_argument(
        "--spf-include",
        dest="spf_includes",
        action="append",
        default=[],
        help="Additional SPF include mechanisms",
    )
    validation_group.add_argument(
        "--spf-ip4",
        dest="spf_ip4",
        action="append",
        default=[],
        help="Additional SPF ip4 mechanisms",
    )
    validation_group.add_argument(
        "--spf-ip6",
        dest="spf_ip6",
        action="append",
        default=[],
        help="Additional SPF ip6 mechanisms",
    )
    validation_group.add_argument(
        "--txt",
        dest="txt_records",
        action="append",
        default=[],
        help="Require TXT record in the form name=value (repeatable)",
    )
    validation_group.add_argument(
        "--txt-verification",
        dest="txt_verification_records",
        action="append",
        default=[],
        help="Require TXT verification record in the form name=value (repeatable)",
    )
    validation_group.add_argument(
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


def _parse_provider_vars(raw_vars: List[str]) -> dict[str, str]:
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
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if args.providers_list:
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

    if not args.provider:
        parser.error("--provider is required unless --providers-list or --provider-show is used")

    try:
        provider = load_provider_config(args.provider)
    except ValueError as exc:
        parser.error(str(exc))

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

    checker = DNSChecker(
        args.domain,
        provider,
        strict=args.strict,
        dmarc_rua_mailto=args.dmarc_rua_mailto,
        dmarc_ruf_mailto=args.dmarc_ruf_mailto,
        dmarc_policy=args.dmarc_policy,
        spf_policy=args.spf_policy,
        additional_spf_includes=args.spf_includes,
        additional_spf_ip4=args.spf_ip4,
        additional_spf_ip6=args.spf_ip6,
        additional_txt=txt_records,
        additional_txt_verification=txt_verification_records,
        skip_txt_verification=args.skip_txt_verification,
    )

    results = checker.run_checks()
    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
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
