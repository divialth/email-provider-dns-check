from pathlib import Path

import pytest

from provider_check.runner import DetectionRequest, run_detection
from provider_check.detection.report import DetectionCandidate, DetectionReport
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
                "    required:",
                "      - host: mx1.dummy.test.",
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


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_run_detection_autoselect_uses_normalized_domain_for_resolve(
    output_format: str,
) -> None:
    captured_domains: list[str] = []
    candidate = DetectionCandidate(
        provider_id="dummy_provider",
        provider_name="Dummy Provider",
        provider_version="1",
        inferred_variables={},
        score=1,
        max_score=1,
        score_ratio=1.0,
        optional_bonus=0,
        status_counts={
            Status.PASS.value: 1,
            Status.WARN.value: 0,
            Status.FAIL.value: 0,
            Status.UNKNOWN.value: 0,
        },
        record_statuses={"MX": Status.PASS.value},
        core_pass_records=["MX"],
    )
    report = DetectionReport(
        domain="example.com",
        candidates=[candidate],
        selected=candidate,
        ambiguous=False,
        status=Status.PASS,
        top_n=3,
    )

    class _DummyProvider:
        name = "Dummy Provider"
        version = "1"

    class _DummyChecker:
        def __init__(self, *_args, **_kwargs):
            pass

        def run_checks(self):
            return []

    def _detect(_domain: str, **_kwargs):
        return report

    def _load_provider(_provider_id: str, **_kwargs):
        return _DummyProvider()

    def _resolve_provider(provider: _DummyProvider, _variables: dict[str, str], **kwargs):
        captured_domains.append(kwargs["domain"])
        return provider

    run_detection(
        DetectionRequest(
            domain=" Example.COM ",
            output=output_format,
            autoselect=True,
            resolver=FakeResolver(),
            detect_providers_fn=_detect,
            load_provider_config_fn=_load_provider,
            resolve_provider_config_fn=_resolve_provider,
            dns_checker_cls=_DummyChecker,
            summarize_status_fn=lambda _results: Status.PASS,
        )
    )

    assert captured_domains == ["example.com"]
