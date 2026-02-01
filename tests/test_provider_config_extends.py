import textwrap

import pytest

from provider_check.provider_config import _normalize_extends, list_providers, load_provider_config


def _write_provider(tmp_path, provider_id: str, content: str) -> None:
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir(exist_ok=True)
    (provider_dir / f"{provider_id}.yaml").write_text(
        textwrap.dedent(content).strip(),
        encoding="utf-8",
    )


def test_extends_merges_and_ignores_base_enabled(monkeypatch, tmp_path):
    _write_provider(
        tmp_path,
        "base",
        """
        enabled: false
        name: Base Provider
        version: 1
        variables:
          token:
            required: true
            description: base token
        records:
          mx:
            hosts:
              - mx.base.test.
          dkim:
            selectors:
              - SEL1
            record_type: cname
            target_template: "{selector}.base.test."
        """,
    )
    _write_provider(
        tmp_path,
        "child",
        """
        name: Child Provider
        version: 1
        extends: base
        variables:
          token:
            required: false
        records:
          dkim:
            target_template: "{selector}.child.test."
          spf:
            required_includes:
              - spf.child.test
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )

    providers = list_providers()
    provider_ids = {provider.provider_id for provider in providers}
    assert "base" not in provider_ids
    assert "child" in provider_ids

    child = load_provider_config("child")
    assert child.mx.hosts == ["mx.base.test."]
    assert child.dkim.target_template == "{selector}.child.test."
    assert child.spf.required_includes == ["spf.child.test"]


def test_extends_allows_removal_with_null(monkeypatch, tmp_path):
    _write_provider(
        tmp_path,
        "base",
        """
        name: Base Provider
        version: 1
        records:
          dkim:
            selectors:
              - SEL1
            record_type: cname
            target_template: "{selector}.base.test."
        """,
    )
    _write_provider(
        tmp_path,
        "no-dkim",
        """
        name: No DKIM Provider
        version: 1
        extends: base
        records:
          dkim: null
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )

    provider = load_provider_config("no-dkim")

    assert provider.dkim is None


def test_extends_multiple_bases(monkeypatch, tmp_path):
    _write_provider(
        tmp_path,
        "base-one",
        """
        name: Base One
        version: 1
        records:
          spf:
            required_includes:
              - spf.one.test
        """,
    )
    _write_provider(
        tmp_path,
        "base-two",
        """
        name: Base Two
        version: 1
        records:
          mx:
            hosts:
              - mx.two.test.
        """,
    )
    _write_provider(
        tmp_path,
        "child",
        """
        name: Child Provider
        version: 1
        extends:
          - base-one
          - base-two
        """,
    )
    import provider_check.provider_config as provider_config

    monkeypatch.setattr(
        provider_config, "_external_provider_dirs", lambda: [tmp_path / "providers"]
    )

    provider = load_provider_config("child")

    assert provider.spf.required_includes == ["spf.one.test"]
    assert provider.mx.hosts == ["mx.two.test."]


def test_extends_invalid_types():
    with pytest.raises(ValueError, match="extends must be a string or list"):
        _normalize_extends("bad", 123)
    with pytest.raises(ValueError, match="extends entries must be strings"):
        _normalize_extends("bad", ["ok", 1])
    with pytest.raises(ValueError, match="extends entries must be non-empty"):
        _normalize_extends("bad", [" "])
