"""Argument parser helpers for the CLI."""

from __future__ import annotations

import argparse
import functools
import logging
import time

from .. import __version__
from .parsing import _parse_dmarc_pct, _parse_positive_float


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
    dns_group = parser.add_argument_group("DNS")
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
    output_group.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Colorize output (disabled when NO_COLOR is set)",
    )
    output_group.add_argument(
        "--no-color",
        dest="color",
        action="store_const",
        const="never",
        help="Disable colorized output",
    )
    dns_group.add_argument(
        "--dns-server",
        dest="dns_servers",
        action="append",
        default=[],
        help="DNS server to use for lookups (repeatable; IP or hostname)",
    )
    dns_group.add_argument(
        "--dns-timeout",
        dest="dns_timeout",
        type=functools.partial(_parse_positive_float, label="DNS timeout"),
        default=None,
        help="Per-query DNS timeout in seconds",
    )
    dns_group.add_argument(
        "--dns-lifetime",
        dest="dns_lifetime",
        type=functools.partial(_parse_positive_float, label="DNS lifetime"),
        default=None,
        help="Total DNS query lifetime in seconds",
    )
    dns_group.add_argument(
        "--dns-tcp",
        dest="dns_tcp",
        action="store_true",
        help="Use TCP for DNS lookups",
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
