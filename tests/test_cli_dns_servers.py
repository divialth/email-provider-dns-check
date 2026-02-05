import pytest

from provider_check.cli import main
from provider_check.detection import DetectionReport
from provider_check.provider_config import ProviderConfig
from provider_check.status import Status


def test_dns_server_option_passed_to_resolver_for_checks(monkeypatch):
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

    captured = {}

    class DummyResolver:
        def __init__(self, nameservers=None, timeout=None, lifetime=None, use_tcp=False):
            captured["nameservers"] = list(nameservers or [])
            captured["timeout"] = timeout
            captured["lifetime"] = lifetime
            captured["use_tcp"] = use_tcp

    class DummyChecker:
        def __init__(self, *_args, **kwargs):
            captured["resolver"] = kwargs.get("resolver")

        def run_checks(self):
            return []

    monkeypatch.setattr(cli, "DnsResolver", DummyResolver)
    monkeypatch.setattr(cli, "DNSChecker", DummyChecker)

    code = main(
        [
            "example.com",
            "--provider",
            "dummy",
            "--output",
            "json",
            "--dns-server",
            "dns.example.test",
            "--dns-server",
            "1.1.1.1",
            "--dns-timeout",
            "2.5",
            "--dns-lifetime",
            "5",
            "--dns-tcp",
        ]
    )

    assert code == 0
    assert captured["nameservers"] == ["dns.example.test", "1.1.1.1"]
    assert captured["timeout"] == 2.5
    assert captured["lifetime"] == 5.0
    assert captured["use_tcp"] is True
    assert isinstance(captured["resolver"], DummyResolver)


def test_dns_server_option_passed_to_detection(monkeypatch):
    import provider_check.cli as cli

    captured = {}

    class DummyResolver:
        def __init__(self, nameservers=None, timeout=None, lifetime=None, use_tcp=False):
            captured["nameservers"] = list(nameservers or [])
            captured["timeout"] = timeout
            captured["lifetime"] = lifetime
            captured["use_tcp"] = use_tcp

    def _fake_detect(_domain, *, resolver=None, top_n=None):
        captured["resolver"] = resolver
        return DetectionReport(
            domain="example.com",
            candidates=[],
            selected=None,
            ambiguous=False,
            status=Status.UNKNOWN,
            top_n=top_n,
        )

    monkeypatch.setattr(cli, "DnsResolver", DummyResolver)
    monkeypatch.setattr(cli, "detect_providers", _fake_detect)

    code = main(
        [
            "example.com",
            "--provider-detect",
            "--output",
            "json",
            "--dns-server",
            "dns.example.test",
            "--dns-timeout",
            "1.25",
            "--dns-lifetime",
            "3",
        ]
    )

    assert code == 3
    assert captured["nameservers"] == ["dns.example.test"]
    assert captured["timeout"] == 1.25
    assert captured["lifetime"] == 3.0
    assert captured["use_tcp"] is False
    assert isinstance(captured["resolver"], DummyResolver)


def test_invalid_dns_server_reports_error(monkeypatch, capsys):
    import provider_check.cli as cli

    def _raise_value_error(*_args, **_kwargs):
        raise ValueError("dns server invalid")

    monkeypatch.setattr(cli, "DnsResolver", _raise_value_error)

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "example.com",
                "--provider-detect",
                "--output",
                "json",
                "--dns-server",
                "bad",
            ]
        )

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "dns server invalid" in err
