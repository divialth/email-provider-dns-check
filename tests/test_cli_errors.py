from argparse import ArgumentTypeError
import json
import logging
from datetime import datetime, timezone

import pytest

from provider_check.checker import RecordCheck
from provider_check.cli import (
    _parse_dmarc_pct,
    _parse_provider_vars,
    _parse_txt_records,
    _setup_logging,
    main,
)
from provider_check.provider_config import ProviderConfig, ProviderVariable


def test_setup_logging_levels(monkeypatch):
    captured = []

    def _fake_basic_config(**kwargs):
        captured.append(kwargs.get("level"))

    monkeypatch.setattr(logging, "basicConfig", _fake_basic_config)

    _setup_logging(1)
    assert captured[-1] == logging.INFO

    _setup_logging(2)
    assert captured[-1] == logging.DEBUG


def test_parse_txt_records_rejects_invalid():
    with pytest.raises(ValueError):
        _parse_txt_records(["missing-delimiter"])
    with pytest.raises(ValueError):
        _parse_txt_records(["=value"])
    with pytest.raises(ValueError):
        _parse_txt_records(["name="])


def test_parse_provider_vars_rejects_invalid():
    with pytest.raises(ValueError):
        _parse_provider_vars(["missing-delimiter"])
    with pytest.raises(ValueError):
        _parse_provider_vars(["=value"])
    with pytest.raises(ValueError):
        _parse_provider_vars(["name="])
    with pytest.raises(ValueError):
        _parse_provider_vars(["dup=1", "dup=2"])


def test_parse_dmarc_pct_rejects_non_integer():
    with pytest.raises(ArgumentTypeError):
        _parse_dmarc_pct("n/a")


def test_parse_dmarc_pct_rejects_out_of_range():
    with pytest.raises(ArgumentTypeError):
        _parse_dmarc_pct("101")


def test_domain_required_without_list_providers(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--provider", "dummy"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "domain is required" in err


def test_invalid_provider_selection_reports_error(monkeypatch, capsys):
    import provider_check.cli as cli

    monkeypatch.setattr(
        cli, "load_provider_config", lambda _selection: (_ for _ in ()).throw(ValueError("nope"))
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "missing"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "nope" in err


def test_invalid_txt_record_reports_error(monkeypatch, capsys):
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

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--txt", "invalid"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "must be in name=value form" in err


def test_missing_provider_var_reports_error(monkeypatch, capsys):
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
        variables={"tenant": ProviderVariable(name="tenant", required=True)},
    )
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Missing required provider variable" in err


def test_unknown_provider_var_reports_error(monkeypatch, capsys):
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
        variables={"tenant": ProviderVariable(name="tenant", required=False)},
    )
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--provider-var", "unknown=1"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Unknown provider variable" in err


def _patch_fixed_datetime(monkeypatch):
    class _FixedDateTime:
        @staticmethod
        def now(tz=None):
            return datetime(2026, 1, 31, 19, 37, tzinfo=timezone.utc)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "datetime", _FixedDateTime)


def test_json_output(monkeypatch, capsys):
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
    _patch_fixed_datetime(monkeypatch)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())
    monkeypatch.setattr(cli, "summarize_status", lambda _results: "PASS")

    code = main(["example.com", "--provider", "dummy", "--output", "json"])
    assert code == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == "example.com"
    assert payload["provider"] == "Dummy"


def test_text_output(monkeypatch, capsys):
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
    _patch_fixed_datetime(monkeypatch)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())
    monkeypatch.setattr(cli, "summarize_status", lambda _results: "PASS")

    code = main(["example.com", "--provider", "dummy", "--output", "text"])
    assert code == 0

    output = capsys.readouterr().out
    assert "report for domain example.com" in output
