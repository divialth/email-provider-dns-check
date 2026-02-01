import pytest

from provider_check import __version__
from provider_check.cli import main


def test_list_providers_outputs_entries(capsys):
    code = main(["--list-providers"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.strip()
    assert "\t" in out
    assert "(v" in out


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
