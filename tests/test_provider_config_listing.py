from importlib import resources
import textwrap

import yaml

from provider_check.provider_config import list_providers, load_provider_config


def _packaged_provider_ids():
    base = resources.files("provider_check.providers")
    provider_ids = {"__disabled__": []}
    for entry in base.iterdir():
        if not entry.is_file() or entry.suffix not in {".yaml", ".yml"}:
            continue
        data = yaml.safe_load(entry.read_text(encoding="utf-8"))
        enabled = data.get("enabled", True)
        if isinstance(enabled, bool):
            is_enabled = enabled
        else:
            is_enabled = str(enabled).lower() not in {"false", "0", "no"}
        if is_enabled:
            provider_ids[entry.stem] = data
        else:
            provider_ids["__disabled__"].append(entry.stem)
    return provider_ids


def test_all_packaged_providers_are_listed():
    packaged = _packaged_provider_ids()
    providers = list_providers()
    listed_ids = {provider.provider_id for provider in providers}

    assert listed_ids
    for provider_id in packaged:
        if provider_id == "__disabled__":
            continue
        assert provider_id in listed_ids

    for provider_id in packaged["__disabled__"]:
        assert provider_id not in listed_ids


def test_each_listed_provider_can_be_loaded():
    providers = list_providers()
    for provider in providers:
        by_id = load_provider_config(provider.provider_id)
        assert by_id.provider_id == provider.provider_id
        by_name = load_provider_config(provider.name)
        assert by_name.provider_id == provider.provider_id


def test_external_providers_override_packaged(monkeypatch, tmp_path):
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    packaged = _packaged_provider_ids()
    enabled_ids = [provider_id for provider_id in packaged if provider_id != "__disabled__"]
    assert enabled_ids
    provider_id = enabled_ids[0]
    override = textwrap.dedent("""
        name: Override Provider
        version: 9
        records:
          mx:
            hosts:
              - mx.override.test.
        """).strip()
    (provider_dir / f"{provider_id}.yaml").write_text(override, encoding="utf-8")

    disabled = textwrap.dedent("""
        enabled: false
        name: Disabled Provider
        version: 1
        records: {}
        """).strip()
    (provider_dir / "disabled.yaml").write_text(disabled, encoding="utf-8")

    import provider_check.provider_config as provider_config

    monkeypatch.setattr(provider_config, "_external_provider_dirs", lambda: [provider_dir])

    providers = list_providers()
    provider_ids = {provider.provider_id for provider in providers}
    assert "disabled" not in provider_ids

    overridden = next(provider for provider in providers if provider.provider_id == provider_id)
    assert overridden.name == "Override Provider"
    assert overridden.version == "9"


def test_packaged_provider_enabled_string_is_parsed(monkeypatch):
    class _FakeEntry:
        def __init__(self, name: str, content: str):
            self.name = name
            self._content = content

        @property
        def suffix(self):
            return ".yaml"

        @property
        def stem(self):
            return self.name.rsplit(".", 1)[0]

        def is_file(self):
            return True

        def read_text(self, encoding="utf-8"):
            return self._content

    class _FakeBase:
        def __init__(self, entries):
            self._entries = entries

        def iterdir(self):
            return list(self._entries)

    content = textwrap.dedent("""
        enabled: "false"
        name: String Disabled
        version: 1
        records: {}
        """).strip()
    base = _FakeBase([_FakeEntry("string-disabled.yaml", content)])
    monkeypatch.setattr(resources, "files", lambda _pkg: base)

    packaged = _packaged_provider_ids()

    assert "string-disabled" in packaged["__disabled__"]
