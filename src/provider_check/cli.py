"""Command-line interface for the DNS checker."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from typing import List

from . import __version__
from .checker import DNSChecker
from .output import summarize_status, to_human, to_json, to_text
from .provider_config import list_providers, load_provider_config


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


def _format_provider_label(name: str, version: str) -> str:
    return f"{name} (v{version})"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check email provider DNS records for a given domain",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", nargs="?", help="Domain to validate")
    parser.add_argument(
        "--provider",
        help="Provider configuration to use (see --list-providers)",
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List available providers and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json", "human"],
        default="human",
        help="Output format",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce exact provider configuration (no extras allowed)",
    )
    parser.add_argument(
        "--dmarc-email",
        dest="dmarc_email",
        help="Email address for DMARC rua reports (mailto: prefix is added automatically)",
    )
    parser.add_argument(
        "--dmarc-policy",
        dest="dmarc_policy",
        choices=["none", "quarantine", "reject"],
        default=None,
        help="DMARC policy (p=). Defaults to provider config.",
    )
    parser.add_argument(
        "--spf-policy",
        dest="spf_policy",
        choices=["softfail", "hardfail"],
        default="hardfail",
        help="SPF policy: softfail (~all) or hardfail (-all)",
    )
    parser.add_argument(
        "--spf-include",
        dest="spf_includes",
        action="append",
        default=[],
        help="Additional SPF include mechanisms",
    )
    parser.add_argument(
        "--spf-ip4",
        dest="spf_ip4",
        action="append",
        default=[],
        help="Additional SPF ip4 mechanisms",
    )
    parser.add_argument(
        "--spf-ip6",
        dest="spf_ip6",
        action="append",
        default=[],
        help="Additional SPF ip6 mechanisms",
    )
    parser.add_argument(
        "--txt",
        dest="txt_records",
        action="append",
        default=[],
        help="Require TXT record in the form name=value (repeatable)",
    )
    parser.add_argument(
        "--txt-verification",
        dest="txt_verification_records",
        action="append",
        default=[],
        help="Require TXT verification record in the form name=value (repeatable)",
    )
    parser.add_argument(
        "--skip-txt-verification",
        action="store_true",
        help="Skip provider-required TXT verification checks",
    )
    parser.add_argument(
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


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if args.list_providers:
        providers = list_providers()
        for provider in providers:
            label = _format_provider_label(provider.name, provider.version)
            print(f"{provider.provider_id}\t{label}")
        return 0

    if not args.domain:
        parser.error("domain is required unless --list-providers is used")

    if not args.provider:
        parser.error("--provider is required unless --list-providers is used")

    try:
        provider = load_provider_config(args.provider)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        txt_records = _parse_txt_records(args.txt_records)
        txt_verification_records = _parse_txt_records(args.txt_verification_records)
    except ValueError as exc:
        parser.error(str(exc))

    checker = DNSChecker(
        args.domain,
        provider,
        strict=args.strict,
        dmarc_email=args.dmarc_email,
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
