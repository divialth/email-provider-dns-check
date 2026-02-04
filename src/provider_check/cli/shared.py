"""Shared CLI helpers."""

from __future__ import annotations

from typing import Dict


def _build_dmarc_required_tags(args: object) -> Dict[str, str]:
    """Build DMARC tag overrides from parsed arguments.

    Args:
        args (object): Parsed CLI arguments.

    Returns:
        Dict[str, str]: DMARC tag overrides to apply.
    """
    dmarc_required_tags: Dict[str, str] = {}
    if getattr(args, "dmarc_subdomain_policy", None):
        dmarc_required_tags["sp"] = args.dmarc_subdomain_policy
    if getattr(args, "dmarc_adkim", None):
        dmarc_required_tags["adkim"] = args.dmarc_adkim
    if getattr(args, "dmarc_aspf", None):
        dmarc_required_tags["aspf"] = args.dmarc_aspf
    if getattr(args, "dmarc_pct", None) is not None:
        dmarc_required_tags["pct"] = str(args.dmarc_pct)
    return dmarc_required_tags
