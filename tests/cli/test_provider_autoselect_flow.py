"""Tests for ``--provider-autoselect`` CLI behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from provider_check.cli import main
from provider_check.detection import DetectionReport
from provider_check.status import Status
from tests.factories import make_record_check

DMARC_STRICT_ARGS = [
    "--dmarc-subdomain-policy",
    "reject",
    "--dmarc-adkim",
    "s",
    "--dmarc-aspf",
    "s",
    "--dmarc-pct",
    "100",
]


def _patch_default_autoselect(
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Patch common autoselect dependencies for a successful lookup flow."""
    patch_cli_datetime(datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc))
    candidate = make_detection_candidate()
    patch_detection_report(make_detection_report(candidate))
    patch_provider_resolution(make_provider())


def test_provider_autoselect_ambiguous_returns_unknown(
    patch_cli_datetime,
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    make_detection_candidate,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Return UNKNOWN when autoselect is ambiguous."""
    patch_cli_datetime(datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc))
    report = DetectionReport(
        domain="example.com",
        candidates=[
            make_detection_candidate(provider_id="a"),
            make_detection_candidate(provider_id="b"),
        ],
        selected=None,
        ambiguous=True,
        status=Status.UNKNOWN,
        top_n=3,
    )
    monkeypatch.setattr(cli_module, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli_module, "DNSChecker", object())

    code = main(["example.com", "--provider-autoselect", "--output", "text"])

    assert code == 3
    assert "provider detection report for domain example.com" in capsys.readouterr().out


def test_provider_autoselect_runs_checks(
    patch_dns_checker,
    capsys: pytest.CaptureFixture[str],
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Run checks after selecting a provider."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check()])

    code = main(["example.com", "--provider-autoselect", "--output", "text"])

    assert code == 0
    output = capsys.readouterr().out
    assert "provider detection report for domain example.com" in output
    assert "report for domain example.com" in output


def test_provider_autoselect_warn_exit(
    patch_dns_checker,
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Return WARN exit code when selected checks have warnings."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check(status=Status.WARN, message="warn")])

    code = main(["example.com", "--provider-autoselect", "--output", "text", *DMARC_STRICT_ARGS])

    assert code == 1


def test_provider_autoselect_human_fail(
    patch_dns_checker,
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Return FAIL exit code in human output mode."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check(status=Status.FAIL, message="fail")])

    code = main(["example.com", "--provider-autoselect", "--output", "human"])

    assert code == 2


@pytest.mark.parametrize(
    ("status", "expected_code"),
    [(Status.PASS, 0), (Status.WARN, 1), (Status.FAIL, 2)],
)
def test_provider_autoselect_json_statuses(
    status: Status,
    expected_code: int,
    patch_dns_checker,
    capsys: pytest.CaptureFixture[str],
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Return expected exit code for JSON output by summarized status."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check(status=status, message="status")])

    code = main(["example.com", "--provider-autoselect", "--output", "json", *DMARC_STRICT_ARGS])

    assert code == expected_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["report"]["provider"] == "Dummy Provider"


def test_provider_autoselect_json_unknown(
    patch_dns_checker,
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Return UNKNOWN exit code when summarize result is UNKNOWN."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check()])
    monkeypatch.setattr(cli_module, "summarize_status", lambda _results: Status.UNKNOWN)

    code = main(["example.com", "--provider-autoselect", "--output", "json"])

    assert code == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_provider_autoselect_invalid_txt_records(
    output_format: str,
    capsys: pytest.CaptureFixture[str],
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Surface parser errors for invalid ``--txt`` inputs."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", output_format, "--txt", "bad"])

    assert exc.value.code == 2
    assert "TXT record" in capsys.readouterr().err


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_provider_autoselect_load_provider_error(
    output_format: str,
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    patch_cli_datetime,
    patch_detection_report,
    make_detection_candidate,
    make_detection_report,
) -> None:
    """Surface provider loading errors in autoselect mode."""
    patch_cli_datetime(datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc))
    candidate = make_detection_candidate()
    patch_detection_report(make_detection_report(candidate))
    monkeypatch.setattr(
        cli_module,
        "load_provider_config",
        lambda _selection: (_ for _ in ()).throw(ValueError("nope")),
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", output_format])

    assert exc.value.code == 2
    assert "nope" in capsys.readouterr().err


def test_provider_autoselect_text_unknown(
    patch_dns_checker,
    cli_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    patch_cli_datetime,
    patch_detection_report,
    patch_provider_resolution,
    make_detection_candidate,
    make_detection_report,
    make_provider,
) -> None:
    """Return UNKNOWN exit code in text mode when summary is UNKNOWN."""
    _patch_default_autoselect(
        patch_cli_datetime,
        patch_detection_report,
        patch_provider_resolution,
        make_detection_candidate,
        make_detection_report,
        make_provider,
    )
    patch_dns_checker([make_record_check()])
    monkeypatch.setattr(cli_module, "summarize_status", lambda _results: Status.UNKNOWN)

    code = main(["example.com", "--provider-autoselect", "--output", "text"])

    assert code == 3
