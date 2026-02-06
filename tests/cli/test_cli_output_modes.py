"""Tests for CLI output rendering and logging behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from provider_check.checker import RecordCheck
from provider_check.cli import main
from provider_check.status import Status


def test_verbose_flag_sets_info_logging(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    patch_provider_resolution,
    patch_dns_checker,
    make_provider,
) -> None:
    """Set INFO log level when ``--verbose`` is used once."""
    captured: dict[str, int] = {}

    def _fake_basic_config(**kwargs):
        captured["level"] = kwargs.get("level")

    monkeypatch.setattr(cli_module.logging, "basicConfig", _fake_basic_config)
    patch_provider_resolution(make_provider(name="Dummy"))
    patch_dns_checker([RecordCheck.pass_("MX", "ok", {"found": ["mx"]})])
    monkeypatch.setattr(cli_module, "summarize_status", lambda _results: Status.PASS)

    code = main(["example.com", "--provider", "dummy", "--verbose", "--output", "json"])

    assert code == 0
    assert captured["level"] == cli_module.logging.INFO


def test_domain_flag_used(
    patch_provider_resolution,
    patch_dns_checker,
    patch_cli_datetime,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Accept ``--domain`` as an alternative to positional domain input."""
    patch_provider_resolution(make_provider(name="Dummy"))
    patch_cli_datetime(datetime(2026, 1, 31, 19, 37, tzinfo=timezone.utc))
    patch_dns_checker([RecordCheck.pass_("MX", "ok", {"found": ["mx"]})])

    code = main(["--domain", "example.com", "--provider", "dummy", "--output", "json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == "example.com"


def test_json_output(
    patch_provider_resolution,
    patch_dns_checker,
    patch_cli_datetime,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Render provider checks in JSON format."""
    patch_provider_resolution(make_provider(name="Dummy"))
    patch_cli_datetime(datetime(2026, 1, 31, 19, 37, tzinfo=timezone.utc))
    patch_dns_checker([RecordCheck.pass_("MX", "ok", {"found": ["mx"]})])

    code = main(["example.com", "--provider", "dummy", "--output", "json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == "example.com"
    assert payload["provider"] == "Dummy"


def test_text_output(
    patch_provider_resolution,
    patch_dns_checker,
    patch_cli_datetime,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Render provider checks in plain text format."""
    patch_provider_resolution(make_provider(name="Dummy"))
    patch_cli_datetime(datetime(2026, 1, 31, 19, 37, tzinfo=timezone.utc))
    patch_dns_checker([RecordCheck.pass_("MX", "ok", {"found": ["mx"]})])

    code = main(["example.com", "--provider", "dummy", "--output", "text"])

    assert code == 0
    assert "report for domain example.com" in capsys.readouterr().out
