"""Provider discovery and path-resolution loader tests."""

from __future__ import annotations

import textwrap

from provider_check.provider_config import list_providers


def test_external_config_dirs_falls_back_to_home(
    monkeypatch,
    provider_config_loader,
) -> None:
    """Use ``~/.config`` fallback when XDG config home is unset."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    dirs = provider_config_loader.external_config_dirs()

    expected = (
        provider_config_loader.Path.home() / ".config" / provider_config_loader.CONFIG_DIR_NAME
    )
    assert dirs[0] == expected


def test_list_providers_skips_invalid_yaml(
    monkeypatch,
    provider_config_loader,
    provider_dir,
) -> None:
    """Skip providers with invalid YAML structure."""
    content = textwrap.dedent("""
        name: Bad Provider
        version: 1
        records: []
        """).strip()
    (provider_dir / "bad.yaml").write_text(content, encoding="utf-8")
    monkeypatch.setattr(provider_config_loader, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config_loader.list_providers()

    assert "bad" not in {provider.provider_id for provider in providers}


def test_list_providers_skips_non_mapping_yaml(
    monkeypatch,
    provider_config_loader,
    fake_path_factory,
) -> None:
    """Skip provider files that parse as non-mapping YAML."""
    monkeypatch.setattr(
        provider_config_loader,
        "_iter_provider_paths",
        lambda: [fake_path_factory("bad.yaml", "- one\n- two\n")],
    )

    providers = provider_config_loader.list_providers()

    assert providers == []


def test_list_providers_skips_unknown_extends(
    monkeypatch,
    provider_config_loader,
    provider_dir,
) -> None:
    """Skip providers that extend unknown base IDs."""
    (provider_dir / "child.yaml").write_text(
        "name: Child\nversion: 1\nextends: missing\nrecords: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(provider_config_loader, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config_loader.list_providers()

    assert "child" not in {provider.provider_id for provider in providers}


def test_list_providers_skips_extends_cycle(
    monkeypatch,
    provider_config_loader,
    provider_dir,
) -> None:
    """Skip providers that form inheritance cycles."""
    (provider_dir / "a.yaml").write_text(
        "name: A\nversion: 1\nextends: b\nrecords: {}\n",
        encoding="utf-8",
    )
    (provider_dir / "b.yaml").write_text(
        "name: B\nversion: 1\nextends: a\nrecords: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(provider_config_loader, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config_loader.list_providers()

    assert "a" not in {provider.provider_id for provider in providers}
    assert "b" not in {provider.provider_id for provider in providers}
