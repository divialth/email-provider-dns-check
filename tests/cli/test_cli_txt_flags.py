from provider_check.cli import main
from provider_check.provider_config import list_providers


class DummyChecker:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def run_checks(self):
        return []


def test_txt_flag_parsing(monkeypatch):
    captured = {}

    def _factory(*args, **kwargs):
        captured["kwargs"] = kwargs
        return DummyChecker(*args, **kwargs)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "DNSChecker", _factory)

    provider_id = list_providers()[0].provider_id
    code = main(["example.com", "--provider", provider_id, "--txt", "_verify=token"])
    assert code == 0
    assert captured["kwargs"]["additional_txt"] == {"_verify": ["token"]}


def test_txt_verification_flag_parsing(monkeypatch):
    captured = {}

    def _factory(*args, **kwargs):
        captured["kwargs"] = kwargs
        return DummyChecker(*args, **kwargs)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "DNSChecker", _factory)

    provider_id = list_providers()[0].provider_id
    code = main(["example.com", "--provider", provider_id, "--txt-verification", "_verify=token"])
    assert code == 0
    assert captured["kwargs"]["additional_txt_verification"] == {"_verify": ["token"]}


def test_skip_txt_verification_flag(monkeypatch):
    captured = {}

    def _factory(*args, **kwargs):
        captured["kwargs"] = kwargs
        return DummyChecker(*args, **kwargs)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "DNSChecker", _factory)

    provider_id = list_providers()[0].provider_id
    code = main(["example.com", "--provider", provider_id, "--skip-txt-verification"])
    assert code == 0
    assert captured["kwargs"]["skip_txt_verification"] is True
