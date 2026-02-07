"""Schema contracts for provider record parser keys."""

from __future__ import annotations

RECORD_SCHEMA: dict[str, dict[str, frozenset[str]]] = {
    "mx": {
        "section": frozenset({"required", "optional"}),
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
        "section": frozenset({"required", "optional"}),
    },
    "aaaa": {
        "section": frozenset({"required", "optional"}),
    },
    "ptr": {
        "section": frozenset({"required", "optional"}),
    },
    "cname": {
        "section": frozenset({"required", "optional"}),
    },
    "caa": {
        "section": frozenset({"required", "optional"}),
    },
    "srv": {
        "section": frozenset({"required", "optional"}),
    },
    "tlsa": {
        "section": frozenset({"required", "optional"}),
    },
    "txt": {
        "section": frozenset({"required", "optional", "settings"}),
        "settings": frozenset({"verification_required"}),
    },
    "dmarc": {
        "section": frozenset({"required", "optional", "settings"}),
        "required": frozenset({"policy", "rua", "ruf", "tags"}),
        "optional": frozenset({"rua", "ruf"}),
        "settings": frozenset({"rua_required", "ruf_required"}),
    },
}
