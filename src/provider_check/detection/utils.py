"""Utility helpers for provider detection."""

from __future__ import annotations

import re
from typing import Dict, Iterable, Sequence

_TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def _normalize_host(host: str) -> str:
    """Normalize a hostname to lowercase and ensure a trailing dot.

    Args:
        host (str): Hostname to normalize.

    Returns:
        str: Normalized hostname ending in a dot.
    """
    return host.rstrip(".").lower() + "."


def _normalize_host_template(template: str) -> str:
    """Normalize a hostname template to include a trailing dot.

    Args:
        template (str): Host template string.

    Returns:
        str: Normalized template with a trailing dot.
    """
    trimmed = template.strip()
    if not trimmed.endswith("."):
        trimmed = trimmed + "."
    return trimmed


def _normalize_record_name(name: str, domain: str) -> str:
    """Normalize a record name relative to a domain.

    Args:
        name (str): Record name or template.
        domain (str): Domain to append when needed.

    Returns:
        str: Fully qualified record name in lowercase without trailing dot.
    """
    trimmed = name.strip()
    if trimmed == "@":
        return domain.lower()
    if "{domain}" in trimmed:
        trimmed = trimmed.replace("{domain}", domain)
    if trimmed.endswith("."):
        return trimmed[:-1].lower()
    trimmed_lower = trimmed.lower()
    domain_lower = domain.lower()
    if trimmed_lower.endswith(domain_lower):
        return trimmed_lower
    if "." in trimmed:
        return trimmed_lower
    return f"{trimmed_lower}.{domain_lower}"


def _template_regex(
    template: str, known_vars: Dict[str, str], capture_vars: Iterable[str]
) -> re.Pattern:
    """Build a regex for matching a template with variables.

    Args:
        template (str): Template string with {var} placeholders.
        known_vars (Dict[str, str]): Variables with fixed values.
        capture_vars (Iterable[str]): Variables to capture from the sample.

    Returns:
        re.Pattern: Compiled regex for matching samples.
    """
    capture_set = set(capture_vars)
    pattern = ""
    idx = 0
    for match in _TEMPLATE_RE.finditer(template):
        pattern += re.escape(template[idx : match.start()])
        var_name = match.group(1)
        if var_name in known_vars:
            pattern += re.escape(known_vars[var_name])
        elif var_name in capture_set:
            pattern += f"(?P<{var_name}>.+?)"
        else:
            pattern += ".+?"
        idx = match.end()
    pattern += re.escape(template[idx:])
    return re.compile(f"^{pattern}$", re.IGNORECASE)


def _match_and_infer(
    template: str,
    samples: Sequence[str],
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
    capture_vars: Iterable[str],
) -> None:
    """Match samples against a template and infer variables.

    Args:
        template (str): Template to match against.
        samples (Sequence[str]): Sample values to test.
        known_vars (Dict[str, str]): Variables with fixed values.
        inferred_vars (Dict[str, str]): Output mapping to update in place.
        capture_vars (Iterable[str]): Variables that can be inferred.
    """
    if not samples:
        return
    regex = _template_regex(template, known_vars, capture_vars)
    for sample in samples:
        match = regex.match(sample)
        if not match:
            continue
        updates = {key: value for key, value in match.groupdict().items() if value is not None}
        if any(
            key in inferred_vars and inferred_vars[key] != value for key, value in updates.items()
        ):
            continue
        for key, value in updates.items():
            inferred_vars.setdefault(key, value)
        break
