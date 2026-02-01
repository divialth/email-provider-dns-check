import textwrap

import pytest

from provider_check.provider_config import list_providers


def _write_external_provider(tmp_path, content: str, provider_id: str = "bad") -> None:
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    (provider_dir / f"{provider_id}.yaml").write_text(
        textwrap.dedent(content).strip(),
        encoding="utf-8",
    )


def test_invalid_records_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records: []
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_spf_list_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          spf:
            required_includes: example.test
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_txt_verification_flag_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            verification_required: "false"
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_txt_required_values_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            required:
              _verify: token
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_short_description_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        short_description:
          - not-a-string
        records: {}
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_long_description_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        long_description:
          - not-a-string
        records: {}
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_enabled_flag_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        enabled: "false"
        name: Invalid Provider
        version: 1
        records: {}
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}
