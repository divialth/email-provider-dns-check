from pathlib import Path

import pytest

from provider_check.provider_config import ProviderConfig
from provider_check.runner import CheckRequest, run_checks
from provider_check.status import Status
from tests.support import FakeResolver


def _write_dummy_provider(tmp_path: Path) -> Path:
    provider_dir = tmp_path / "providers"
    provider_dir.mkdir()
    provider_path = provider_dir / "dummy_provider.yaml"
    provider_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "name: Dummy Provider",
                "records:",
                "  mx:",
                "    hosts:",
                "      - mx1.dummy.test.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return provider_dir


def test_run_checks_success(tmp_path: Path) -> None:
    provider_dir = _write_dummy_provider(tmp_path)
    resolver = FakeResolver(
        mx={"example.com": [("mx1.dummy.test.", 10)]},
    )
    result = run_checks(
        CheckRequest(
            domain="example.com",
            provider_id="dummy_provider",
            provider_dirs=[provider_dir],
            output="text",
            resolver=resolver,
        )
    )
    assert result.exit_code == 0
    assert result.status is Status.PASS
    assert "report for domain example.com" in result.output


def test_run_checks_unknown_provider(tmp_path: Path) -> None:
    provider_dir = _write_dummy_provider(tmp_path)
    with pytest.raises(ValueError, match="Unknown provider"):
        run_checks(
            CheckRequest(
                domain="example.com",
                provider_id="missing_provider",
                provider_dirs=[provider_dir],
                output="text",
            )
        )


def test_run_checks_loader_fallback(tmp_path: Path) -> None:
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

    def _loader(_selection: str) -> ProviderConfig:
        return provider

    result = run_checks(
        CheckRequest(
            domain="example.com",
            provider_id="dummy",
            provider_dirs=[tmp_path],
            output="text",
            load_provider_config_fn=_loader,
            resolve_provider_config_fn=lambda prov, *_args, **_kwargs: prov,
        )
    )
    assert result.exit_code == 0
