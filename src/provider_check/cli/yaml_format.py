"""YAML rendering helpers for CLI output."""

from __future__ import annotations

import yaml


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
