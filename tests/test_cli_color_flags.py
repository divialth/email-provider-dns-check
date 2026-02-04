from provider_check.checker import RecordCheck
from provider_check.cli import main
from provider_check.provider_config import ProviderConfig


def _patch_provider_and_checker(monkeypatch, status: str = "PASS") -> None:
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", status, "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())


def test_color_always_emits_ansi(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    _patch_provider_and_checker(monkeypatch)

    code = main(["example.com", "--provider", "dummy", "--output", "text", "--color", "always"])

    assert code == 0
    out = capsys.readouterr().out
    assert "\x1b[" in out


def test_no_color_overrides_always(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    _patch_provider_and_checker(monkeypatch)

    code = main(["example.com", "--provider", "dummy", "--output", "text", "--color", "always"])

    assert code == 0
    out = capsys.readouterr().out
    assert "\x1b[" not in out
