"""Tests for CLI argument validation and error paths."""

from __future__ import annotations

from typing import Any

import pytest

from provider_check.cli import main
from provider_check.provider_config import ProviderVariable


def test_domain_required_without_list_providers(capsys: pytest.CaptureFixture[str]) -> None:
    """Require a domain when provider listing/show is not requested."""
    with pytest.raises(SystemExit) as exc:
        main(["--provider", "dummy"])

    assert exc.value.code == 2
    assert "domain is required" in capsys.readouterr().err


def test_domain_flag_conflicts_with_positional(capsys: pytest.CaptureFixture[str]) -> None:
    """Reject simultaneous positional and ``--domain`` inputs."""
    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--domain", "other.com", "--provider", "dummy"])

    assert exc.value.code == 2
    assert "positional or via --domain" in capsys.readouterr().err


def test_provider_detect_limit_requires_detection(capsys: pytest.CaptureFixture[str]) -> None:
    """Reject ``--provider-detect-limit`` without detection mode."""
    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--provider-detect-limit", "5"])

    assert exc.value.code == 2
    assert "--provider-detect-limit requires" in capsys.readouterr().err


def test_domain_flag_with_providers_list(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allow ``--domain`` when listing providers."""
    monkeypatch.setattr(cli_module, "list_providers", lambda: [])

    code = main(["--domain", "example.com", "--providers-list"])

    assert code == 0


def test_domain_flag_conflicts_with_positional_even_with_providers_list(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Preserve positional/flag domain conflict checks for provider listing."""
    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--domain", "other.com", "--providers-list"])

    assert exc.value.code == 2
    assert "positional or via --domain" in capsys.readouterr().err


def test_invalid_provider_selection_reports_error(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Surface provider selection errors from loader functions."""
    monkeypatch.setattr(
        cli_module,
        "load_provider_config",
        lambda _selection: (_ for _ in ()).throw(ValueError("nope")),
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "missing"])

    assert exc.value.code == 2
    assert "nope" in capsys.readouterr().err


def test_invalid_txt_record_reports_error(
    patch_provider_resolution,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject malformed ``--txt`` command-line values."""
    patch_provider_resolution(make_provider(name="Dummy"))

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--txt", "invalid"])

    assert exc.value.code == 2
    assert "must be in name=value form" in capsys.readouterr().err


def test_missing_provider_var_reports_error(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject missing required provider variables."""
    provider = make_provider(
        name="Dummy",
        variables={"tenant": ProviderVariable(name="tenant", required=True)},
    )
    monkeypatch.setattr(cli_module, "load_provider_config", lambda _selection: provider)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy"])

    assert exc.value.code == 2
    assert "Missing required provider variable" in capsys.readouterr().err


def test_unknown_provider_var_reports_error(
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    make_provider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject unknown provider variables passed via command line."""
    provider = make_provider(
        name="Dummy",
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    monkeypatch.setattr(cli_module, "load_provider_config", lambda _selection: provider)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--provider-var", "unknown=1"])

    assert exc.value.code == 2
    assert "Unknown provider variable" in capsys.readouterr().err
