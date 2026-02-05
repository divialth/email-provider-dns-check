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
    import provider_check.provider_config.loader as provider_config

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
            required:
              includes: example.test
        """,
    )
    import provider_check.provider_config.loader as provider_config

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
            settings:
              verification_required: "false"
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_txt_records_values_rejected(monkeypatch, tmp_path):
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
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_txt_optional_values_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          txt:
            optional:
              _verify: token
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_a_records_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          a:
            required:
              "@": 192.0.2.1
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_aaaa_records_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          aaaa:
            required:
              "@": 2001:db8::1
        """,
    )
    import provider_check.provider_config.loader as provider_config

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
    import provider_check.provider_config.loader as provider_config

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
    import provider_check.provider_config.loader as provider_config

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
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variables_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables: []
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variable_required_flag_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          tenant:
            required: "yes"
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_reserved_variable_name_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          domain:
            required: true
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variable_key_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          1:
            required: true
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_empty_variable_key_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          "": {}
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variable_spec_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          token: value
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variable_default_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          token:
            default: 123
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_variable_description_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        variables:
          token:
            description:
              - not-a-string
        records: {}
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_variable_null_spec_is_accepted(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Valid Provider
        version: 1
        variables:
          token:
        records: {}
        """,
        provider_id="valid",
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "valid" in {provider.provider_id for provider in providers}


def test_invalid_cname_records_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          cname:
            required:
              - not-a-map
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_cname_value_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          cname:
            required:
              sip:
                target: sip.provider.test.
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_srv_records_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls: invalid
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_srv_entry_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls:
                - target: sip.provider.test.
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_srv_entry_type_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          srv:
            required:
              _sip._tls:
                - not-a-map
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_dmarc_rua_required_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          dmarc:
            settings:
              rua_required: "false"
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_invalid_dmarc_ruf_required_rejected(monkeypatch, tmp_path):
    _write_external_provider(
        tmp_path,
        """
        name: Invalid Provider
        version: 1
        records:
          dmarc:
            settings:
              ruf_required: "false"
        """,
    )
    import provider_check.provider_config.loader as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )
    providers = list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}
