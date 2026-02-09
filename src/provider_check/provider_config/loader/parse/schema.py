"""Schema contracts for provider record parser keys."""

from __future__ import annotations

RECORD_SCHEMA: dict[str, dict[str, frozenset[str]]] = {
    "mx": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
        "negative": frozenset({"policy", "entries"}),
        "policy": frozenset({"match"}),
    },
    "spf": {
        "section": frozenset({"required", "optional"}),
        "required": frozenset({"policy", "includes", "mechanisms", "modifiers"}),
        "optional": frozenset({"mechanisms", "modifiers"}),
    },
    "dkim": {
        "section": frozenset({"required"}),
        "required": frozenset({"selectors", "record_type", "target_template", "txt_values"}),
    },
    "a": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "aaaa": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "ptr": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "cname": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "caa": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "srv": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "tlsa": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden"}),
    },
    "txt": {
        "section": frozenset({"required", "optional", "deprecated", "forbidden", "settings"}),
        "settings": frozenset({"verification_required"}),
    },
    "dmarc": {
        "section": frozenset({"required", "optional", "settings"}),
        "required": frozenset({"policy", "rua", "ruf", "tags"}),
        "optional": frozenset({"rua", "ruf"}),
        "settings": frozenset({"rua_required", "ruf_required"}),
    },
}
