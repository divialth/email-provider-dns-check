"""JSON Schema validation tests for bundled provider YAML files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


def _collect_errors(validator: Draft202012Validator, payload: object, label: str) -> list[str]:
    """Collect schema validation errors for one provider payload.

    Args:
        validator (Draft202012Validator): JSON Schema validator.
        payload (object): Provider YAML content.
        label (str): Friendly path label for error output.

    Returns:
        list[str]: Rendered validation error lines.
    """
    errors: list[str] = []
    for err in validator.iter_errors(payload):
        location = ".".join(str(part) for part in err.absolute_path) or "<root>"
        errors.append(f"{label}:{location}: {err.message}")
    return errors


def test_bundled_provider_yaml_matches_schema() -> None:
    """Validate bundled provider YAML definitions against the JSON Schema."""
    root = Path(__file__).resolve().parents[2]
    schema_path = root / "src/provider_check/resources/providers/provider.schema.json"
    providers_dir = root / "src/provider_check/resources/providers"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    errors: list[str] = []
    for path in sorted(providers_dir.glob("*.y*ml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors.extend(_collect_errors(validator, payload, path.name))

    assert not errors, "\n".join(errors)


def test_provider_yaml_schema_reports_invalid_payload() -> None:
    """Ensure invalid provider payloads produce explicit schema errors."""
    root = Path(__file__).resolve().parents[2]
    schema_path = root / "src/provider_check/resources/providers/provider.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    payload = {"name": "Broken Provider", "records": {"spf": {"required": {"includes": []}}}}

    errors = _collect_errors(validator, payload, "broken.yaml")

    assert errors
    assert any("version" in error or "policy" in error for error in errors)
