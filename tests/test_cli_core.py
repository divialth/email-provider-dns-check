import pytest

from provider_check import __version__
from provider_check.cli import main


def test_list_providers_outputs_entries(capsys):
    code = main(["--providers-list"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.strip()
    assert "  v" in out


def test_list_providers_handles_empty(capsys, monkeypatch):
    import provider_check.cli as cli

    monkeypatch.setattr(cli, "list_providers", lambda: [])

    code = main(["--providers-list"])
    assert code == 0
    out = capsys.readouterr().out
    assert out == ""


def test_provider_show_outputs_yaml(capsys, monkeypatch):
    import provider_check.cli as cli
    from provider_check.provider_config import ProviderConfig

    provider = ProviderConfig(
        provider_id="dummy_provider",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
        short_description="Short summary.",
        long_description="Long description line 1.\nLong description line 2.",
    )
    data = {
        "name": "Dummy Provider",
        "version": 1,
        "short_description": provider.short_description,
        "long_description": provider.long_description,
        "records": {},
    }
    monkeypatch.setattr(cli, "load_provider_config_data", lambda _selection: (provider, data))

    code = main(["--provider-show", "dummy_provider"])
    assert code == 0
    out = capsys.readouterr().out
    assert "name: Dummy Provider" in out
    assert "records:" in out
    assert "short_description:" in out
    assert "long_description:" in out
    assert "long_description: |" not in out
    assert "long_description:\n  Long description line 1." in out


def test_provider_show_unknown_reports_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--provider-show", "missing-provider"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Unknown provider" in err


def test_strip_long_description_indicator_noop():
    from provider_check.cli import _strip_long_description_indicator

    rendered = "name: Dummy Provider\n"
    assert _strip_long_description_indicator(rendered) == rendered


def test_provider_required_without_list_providers(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["example.com"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--provider is required" in err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert out.strip().endswith(__version__)
