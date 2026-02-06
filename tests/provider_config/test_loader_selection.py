"""Provider selection and source-resolution loader tests."""

from __future__ import annotations

import textwrap

import pytest

from provider_check.provider_config import load_provider_config


def test_load_provider_config_requires_selection() -> None:
    """Require a non-empty provider selection."""
    with pytest.raises(ValueError):
        load_provider_config("")


def test_load_provider_config_matches_name(
    monkeypatch: pytest.MonkeyPatch,
    provider_config_loader,
    make_provider_config,
) -> None:
    """Load provider by display name."""
    provider = make_provider_config(provider_id="dummy_id", name="Friendly Mail")
    monkeypatch.setattr(provider_config_loader, "list_providers", lambda: [provider])

    loaded = load_provider_config("Friendly Mail")

    assert loaded.provider_id == "dummy_id"


def test_load_provider_config_unknown_raises(
    monkeypatch: pytest.MonkeyPatch,
    provider_config_loader,
) -> None:
    """Include available providers in unknown-provider errors."""
    monkeypatch.setattr(provider_config_loader, "list_providers", lambda: [])

    with pytest.raises(ValueError) as exc:
        load_provider_config("missing")

    assert "Available: none" in str(exc.value)


def test_load_provider_config_data_missing_source_raises(
    monkeypatch: pytest.MonkeyPatch,
    provider_config_loader,
    make_provider_config,
    fake_path_factory,
) -> None:
    """Fail when resolved provider source exists but is disabled."""
    provider = make_provider_config(provider_id="missing", name="Missing Provider")
    content = textwrap.dedent("""
        enabled: false
        name: Disabled Provider
        version: 1
        records: {}
        """).strip()
    monkeypatch.setattr(provider_config_loader, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(
        provider_config_loader,
        "_iter_provider_paths",
        lambda: [fake_path_factory("missing.yaml", content)],
    )

    with pytest.raises(ValueError) as exc:
        provider_config_loader.load_provider_config_data("missing")

    assert "source not found" in str(exc.value)


def test_load_provider_config_data_source_not_present_raises(
    monkeypatch: pytest.MonkeyPatch,
    provider_config_loader,
    make_provider_config,
) -> None:
    """Fail when source provider file is absent."""
    provider = make_provider_config(provider_id="missing", name="Missing Provider")
    monkeypatch.setattr(provider_config_loader, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(provider_config_loader, "_iter_provider_paths", lambda: [])

    with pytest.raises(ValueError) as exc:
        provider_config_loader.load_provider_config_data("missing")

    assert "source not found" in str(exc.value)


def test_load_provider_config_data_returns_source(
    monkeypatch: pytest.MonkeyPatch,
    provider_config_loader,
    make_provider_config,
    fake_path_factory,
) -> None:
    """Return provider config and source data mapping when present."""
    provider = make_provider_config(provider_id="dummy", name="Dummy Provider")
    content = textwrap.dedent("""
        name: Dummy Provider
        version: 1
        records: {}
        """).strip()
    other_content = textwrap.dedent("""
        name: Other Provider
        version: 1
        records: {}
        """).strip()
    monkeypatch.setattr(provider_config_loader, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(
        provider_config_loader,
        "_iter_provider_paths",
        lambda: [
            fake_path_factory("other.yaml", other_content),
            fake_path_factory("dummy.yaml", content),
        ],
    )

    loaded, data = provider_config_loader.load_provider_config_data("dummy")

    assert loaded.provider_id == "dummy"
    assert data["name"] == "Dummy Provider"
