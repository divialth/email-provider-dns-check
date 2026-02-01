from provider_check.cli import main
from provider_check.provider_config import list_providers


def test_exit_codes_from_summary(monkeypatch):
    import provider_check.cli as cli

    class _DummyChecker:
        def __init__(self, *_args, **_kwargs):
            pass

        def run_checks(self):
            return []

    def _factory(*args, **kwargs):
        return _DummyChecker()

    monkeypatch.setattr(cli, "DNSChecker", _factory)

    def _run_with_status(status: str) -> int:
        monkeypatch.setattr(cli, "summarize_status", lambda _results: status)
        provider_id = list_providers()[0].provider_id
        return main(["example.com", "--provider", provider_id])

    assert _run_with_status("PASS") == 0
    assert _run_with_status("WARN") == 1
    assert _run_with_status("FAIL") == 2
    assert _run_with_status("UNKNOWN") == 3
