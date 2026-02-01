from provider_check.cli import main
from provider_check.provider_config import list_providers


class DummyChecker:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def run_checks(self):
        return []


def test_dmarc_flag_parsing(monkeypatch):
    captured = {}

    def _factory(*args, **kwargs):
        captured["kwargs"] = kwargs
        return DummyChecker(*args, **kwargs)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "DNSChecker", _factory)

    provider_id = list_providers()[0].provider_id
    code = main(
        [
            "example.com",
            "--provider",
            provider_id,
            "--dmarc-subdomain-policy",
            "reject",
            "--dmarc-adkim",
            "s",
            "--dmarc-aspf",
            "r",
            "--dmarc-pct",
            "50",
            "--dmarc-policy",
            "quarantine",
        ]
    )
    assert code == 0
    assert captured["kwargs"]["dmarc_policy"] == "quarantine"
    assert captured["kwargs"]["dmarc_required_tags"] == {
        "sp": "reject",
        "adkim": "s",
        "aspf": "r",
        "pct": "50",
    }
