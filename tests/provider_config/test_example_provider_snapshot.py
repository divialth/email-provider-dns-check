"""Snapshot test for the canonical example provider configuration."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


def test_example_provider_yaml_snapshot() -> None:
    """Keep the canonical example provider config synchronized with its snapshot."""
    root = Path(__file__).resolve().parents[2]
    example_path = root / "src/provider_check/resources/providers/example_do_not_use.yaml"
    snapshot_path = root / "tests/provider_config/snapshots/example_do_not_use.normalized.json"
    payload = yaml.safe_load(example_path.read_text(encoding="utf-8"))
    normalized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    snapshot = snapshot_path.read_text(encoding="utf-8")

    assert normalized == snapshot
