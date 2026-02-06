"""Tests for ``--provider-detect`` CLI behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from provider_check.cli import main


def test_provider_detect_outputs_json(
    patch_cli_datetime,
    patch_detection_report,
    make_detection_candidate,
    make_detection_report,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Return JSON output with selected provider details."""
    patch_cli_datetime(datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc))
    candidate = make_detection_candidate()
    patch_detection_report(make_detection_report(candidate))

    code = main(["example.com", "--provider-detect", "--output", "json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    assert payload["selected_provider"]["provider_id"] == "dummy"
    assert payload["candidates"][0]["provider_id"] == "dummy"


def test_provider_detect_limit_passed_to_detection(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    make_detection_candidate,
    make_detection_report,
) -> None:
    """Forward ``--provider-detect-limit`` to detection implementation."""
    candidate = make_detection_candidate()
    captured: dict[str, int] = {}

    def _fake_detect(_domain, *, resolver=None, top_n=None):
        captured["top_n"] = top_n
        return make_detection_report(candidate, top_n=top_n)

    monkeypatch.setattr(cli_module, "detect_providers", _fake_detect)

    code = main(
        [
            "example.com",
            "--provider-detect",
            "--provider-detect-limit",
            "5",
            "--output",
            "json",
        ]
    )

    assert code == 0
    assert captured["top_n"] == 5


def test_provider_detect_passes_provider_dirs(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    make_detection_candidate,
    make_detection_report,
) -> None:
    """Forward ``--providers-dir`` values to detection implementation."""
    candidate = make_detection_candidate()
    captured: dict[str, list] = {}

    def _fake_detect(_domain, *, resolver=None, top_n=None, provider_dirs=None):
        captured["provider_dirs"] = provider_dirs
        return make_detection_report(candidate, top_n=top_n)

    monkeypatch.setattr(cli_module, "detect_providers", _fake_detect)

    code = main(
        [
            "example.com",
            "--provider-detect",
            "--providers-dir",
            str(tmp_path),
            "--output",
            "json",
        ]
    )

    assert code == 0
    assert captured["provider_dirs"] == [tmp_path]


def test_provider_detect_flag_conflicts(
    patch_cli_datetime,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject incompatible provider detection flag combinations."""
    patch_cli_datetime(datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc))

    with pytest.raises(SystemExit) as first:
        main(["example.com", "--provider-detect", "--provider-autoselect"])
    assert first.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err

    with pytest.raises(SystemExit) as second:
        main(["example.com", "--provider", "dummy", "--provider-detect"])
    assert second.value.code == 2
    assert "--provider cannot be used" in capsys.readouterr().err

    with pytest.raises(SystemExit) as third:
        main(["example.com", "--provider-detect", "--provider-var", "foo=bar"])
    assert third.value.code == 2
    assert "--provider-var is not supported" in capsys.readouterr().err
