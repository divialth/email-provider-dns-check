from provider_check.checker import RecordCheck
from provider_check.cli import main
from provider_check.status import Status

from tests.factories import make_provider_config


def _patch_provider_and_checker(monkeypatch, status: Status = Status.PASS) -> None:
    import provider_check.cli as cli

    provider = make_provider_config(provider_id="dummy", name="Dummy")
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck.with_status("MX", status, "ok", {"found": ["mx"]})]

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


def test_no_color_flag_disables_color(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    _patch_provider_and_checker(monkeypatch)

    code = main(["example.com", "--provider", "dummy", "--output", "text", "--no-color"])

    assert code == 0
    out = capsys.readouterr().out
    assert "\x1b[" not in out


def test_color_never_disables_color(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    _patch_provider_and_checker(monkeypatch)

    code = main(["example.com", "--provider", "dummy", "--output", "text", "--color", "never"])

    assert code == 0
    out = capsys.readouterr().out
    assert "\x1b[" not in out
