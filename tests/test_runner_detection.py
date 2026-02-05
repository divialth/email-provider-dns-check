from pathlib import Path

import pytest

from provider_check.runner import DetectionRequest, run_detection
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


def test_run_detection_autoselect_text(tmp_path: Path) -> None:
    provider_dir = _write_dummy_provider(tmp_path)
    resolver = FakeResolver(
        mx={"example.com": [("mx1.dummy.test.", 10)]},
    )
    result = run_detection(
        DetectionRequest(
            domain="example.com",
            provider_dirs=[provider_dir],
            output="text",
            autoselect=True,
            resolver=resolver,
        )
    )
    assert result.exit_code == 0
    assert "provider detection report" in result.output
    assert "report for domain example.com" in result.output


def test_run_detection_invalid_output(tmp_path: Path) -> None:
    provider_dir = _write_dummy_provider(tmp_path)
    with pytest.raises(ValueError, match="Unsupported output format"):
        run_detection(
            DetectionRequest(
                domain="example.com",
                provider_dirs=[provider_dir],
                output="csv",
            )
        )
