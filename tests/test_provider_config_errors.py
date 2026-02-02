import textwrap

import pytest

import provider_check.provider_config as provider_config
from provider_check.provider_config import ProviderConfig, load_provider_config


def test_require_mapping_rejects_missing_or_invalid():
    with pytest.raises(ValueError):
        provider_config._require_mapping("dummy", "records", None)
    with pytest.raises(ValueError):
        provider_config._require_mapping("dummy", "records", [])


def test_require_list_rejects_missing_or_invalid():
    with pytest.raises(ValueError):
        provider_config._require_list("dummy", "mx hosts", None)
    with pytest.raises(ValueError):
        provider_config._require_list("dummy", "mx hosts", {})


def test_load_yaml_requires_mapping(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("- item", encoding="utf-8")

    with pytest.raises(ValueError):
        provider_config._load_yaml(path)


def test_load_provider_missing_version_raises():
    with pytest.raises(ValueError):
        provider_config._load_provider_from_data("bad", {"name": "Bad", "records": {}})


def test_external_config_dirs_falls_back_to_home(monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    dirs = provider_config.external_config_dirs()

    expected = provider_config.Path.home() / ".config" / provider_config.CONFIG_DIR_NAME
    assert dirs[0] == expected


def test_load_provider_records_optional():
    data = {"version": "1", "name": "Optional Records"}

    config = provider_config._load_provider_from_data("optional", data)

    assert config.mx is None
    assert config.spf is None


def test_load_provider_mx_record_requires_mapping():
    data = {
        "version": "1",
        "records": {"mx": {"hosts": ["mx.example."], "records": ["not-a-map"]}},
    }

    with pytest.raises(ValueError):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_mx_record_requires_host_and_priority():
    data = {
        "version": "1",
        "records": {"mx": {"hosts": ["mx.example."], "records": [{"host": "mx.example."}]}},
    }

    with pytest.raises(ValueError):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_mx_hosts_added_from_records_and_priorities():
    data = {
        "version": "1",
        "records": {
            "mx": {
                "hosts": [],
                "records": [{"host": "mx1.example.", "priority": 10}],
                "priorities": {"mx2.example.": 20},
            }
        },
    }

    config = provider_config._load_provider_from_data("mx", data)

    assert config.mx is not None
    assert "mx1.example." in config.mx.hosts
    assert "mx2.example." in config.mx.hosts


def test_load_provider_dkim_record_type_invalid():
    data = {
        "version": "1",
        "records": {"dkim": {"selectors": ["s1"], "record_type": "invalid"}},
    }

    with pytest.raises(ValueError):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_dkim_cname_requires_target_template():
    data = {
        "version": "1",
        "records": {"dkim": {"selectors": ["s1"], "record_type": "cname"}},
    }

    with pytest.raises(ValueError):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_cname_optional_requires_string():
    data = {
        "version": "1",
        "records": {"cname": {"records_optional": {"autoconfig": {"bad": "value"}}}},
    }

    with pytest.raises(ValueError, match="cname records_optional"):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_srv_optional_requires_mapping_entries():
    data = {
        "version": "1",
        "records": {"srv": {"records_optional": {"_autodiscover._tcp": ["not-a-map"]}}},
    }

    with pytest.raises(ValueError, match="srv records_optional._autodiscover._tcp entries"):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_srv_optional_requires_priority_fields():
    data = {
        "version": "1",
        "records": {
            "srv": {"records_optional": {"_autodiscover._tcp": [{"priority": 0, "weight": 0}]}}
        },
    }

    with pytest.raises(ValueError, match="srv records_optional._autodiscover._tcp entries require"):
        provider_config._load_provider_from_data("bad", data)


def test_load_provider_txt_required_values_loaded():
    data = {
        "version": "1",
        "records": {"txt": {"required": {"_verify": ["token-1", "token-2"]}}},
    }

    config = provider_config._load_provider_from_data("txt", data)

    assert config.txt is not None
    assert config.txt.required == {"_verify": ["token-1", "token-2"]}


def test_load_provider_config_requires_selection():
    with pytest.raises(ValueError):
        load_provider_config("")


def test_load_provider_config_matches_name(monkeypatch):
    provider = ProviderConfig(
        provider_id="dummy_id",
        name="Friendly Mail",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(provider_config, "list_providers", lambda: [provider])

    loaded = load_provider_config("Friendly Mail")
    assert loaded.provider_id == "dummy_id"


def test_load_provider_config_unknown_raises(monkeypatch):
    monkeypatch.setattr(provider_config, "list_providers", lambda: [])

    with pytest.raises(ValueError) as exc:
        load_provider_config("missing")

    assert "Available: none" in str(exc.value)


def test_load_provider_config_data_missing_source_raises(monkeypatch):
    class _FakePath:
        def __init__(self, name: str, content: str):
            self.name = name
            self._content = content

        def read_text(self, encoding="utf-8"):
            return self._content

    provider = ProviderConfig(
        provider_id="missing",
        name="Missing Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    content = textwrap.dedent("""
        enabled: false
        name: Disabled Provider
        version: 1
        records: {}
        """).strip()
    monkeypatch.setattr(provider_config, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(
        provider_config,
        "_iter_provider_paths",
        lambda: [_FakePath("missing.yaml", content)],
    )

    with pytest.raises(ValueError) as exc:
        provider_config.load_provider_config_data("missing")

    assert "source not found" in str(exc.value)


def test_load_provider_config_data_source_not_present_raises(monkeypatch):
    provider = ProviderConfig(
        provider_id="missing",
        name="Missing Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(provider_config, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(provider_config, "_iter_provider_paths", lambda: [])

    with pytest.raises(ValueError) as exc:
        provider_config.load_provider_config_data("missing")

    assert "source not found" in str(exc.value)


def test_load_provider_config_data_returns_source(monkeypatch):
    class _FakePath:
        def __init__(self, name: str, content: str):
            self.name = name
            self._content = content

        def read_text(self, encoding="utf-8"):
            return self._content

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    content = textwrap.dedent("""
        name: Dummy Provider
        version: 1
        records: {}
        """).strip()
    monkeypatch.setattr(provider_config, "load_provider_config", lambda _selection: provider)
    other_content = textwrap.dedent("""
        name: Other Provider
        version: 1
        records: {}
        """).strip()
    monkeypatch.setattr(
        provider_config,
        "_iter_provider_paths",
        lambda: [
            _FakePath("other.yaml", other_content),
            _FakePath("dummy.yaml", content),
        ],
    )

    loaded, data = provider_config.load_provider_config_data("dummy")

    assert loaded.provider_id == "dummy"
    assert data["name"] == "Dummy Provider"


def test_list_providers_skips_invalid_yaml(monkeypatch, tmp_path):
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    content = textwrap.dedent("""
        name: Bad Provider
        version: 1
        records: []
        """).strip()
    (provider_dir / "bad.yaml").write_text(content, encoding="utf-8")

    monkeypatch.setattr(provider_config, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config.list_providers()
    assert "bad" not in {provider.provider_id for provider in providers}


def test_list_providers_skips_non_mapping_yaml(monkeypatch):
    class _FakePath:
        def __init__(self, name: str, content: str):
            self.name = name
            self._content = content

        def read_text(self, encoding="utf-8"):
            return self._content

    monkeypatch.setattr(
        provider_config,
        "_iter_provider_paths",
        lambda: [_FakePath("bad.yaml", "- one\n- two\n")],
    )

    providers = provider_config.list_providers()

    assert providers == []


def test_list_providers_skips_unknown_extends(monkeypatch, tmp_path):
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    (provider_dir / "child.yaml").write_text(
        "name: Child\nversion: 1\nextends: missing\nrecords: {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(provider_config, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config.list_providers()

    assert "child" not in {provider.provider_id for provider in providers}


def test_list_providers_skips_extends_cycle(monkeypatch, tmp_path):
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    (provider_dir / "a.yaml").write_text(
        "name: A\nversion: 1\nextends: b\nrecords: {}\n", encoding="utf-8"
    )
    (provider_dir / "b.yaml").write_text(
        "name: B\nversion: 1\nextends: a\nrecords: {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(provider_config, "_external_provider_dirs", lambda: [provider_dir])

    providers = provider_config.list_providers()

    assert "a" not in {provider.provider_id for provider in providers}
    assert "b" not in {provider.provider_id for provider in providers}
