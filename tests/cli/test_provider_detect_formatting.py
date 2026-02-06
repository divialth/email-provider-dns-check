"""Tests for provider-detection output formatting helpers."""

from __future__ import annotations

from provider_check.cli import _build_detection_payload, _format_detection_report
from provider_check.status import Status


def test_format_detection_report_handles_empty_candidates(make_detection_report) -> None:
    """Render an explicit message when no candidates are detected."""
    report = make_detection_report(None, status=Status.UNKNOWN, ambiguous=False, selected=False)

    output = _format_detection_report(report, "2026-02-02 12:00")

    assert "No matching providers detected." in output


def test_format_detection_report_includes_vars_and_na_score(
    make_detection_candidate,
    make_detection_report,
) -> None:
    """Render inferred variables and n/a score when max score is zero."""
    candidate = make_detection_candidate(
        inferred_variables={"tenant": "acme"},
        score=0,
        max_score=0,
        score_ratio=0.0,
        status_counts={"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0},
        record_statuses={},
        core_pass_records=[],
    )
    report = make_detection_report(
        candidate, status=Status.UNKNOWN, ambiguous=False, selected=False
    )

    output = _format_detection_report(report, "2026-02-02 12:00")

    assert "score n/a" in output
    assert "vars: tenant=acme" in output


def test_format_detection_report_includes_optional_bonus(
    make_detection_candidate,
    make_detection_report,
) -> None:
    """Render optional bonus when it is present on a candidate."""
    candidate = make_detection_candidate(optional_bonus=3)
    report = make_detection_report(candidate, status=Status.PASS, ambiguous=False, selected=True)

    output = _format_detection_report(report, "2026-02-02 12:00")

    assert "optional bonus: 3" in output


def test_build_detection_payload_without_selected_provider(make_detection_report) -> None:
    """Emit ``selected_provider`` as null when nothing is selected."""
    report = make_detection_report(None, status=Status.UNKNOWN, ambiguous=False, selected=False)

    payload = _build_detection_payload(report, "2026-02-02 12:00")

    assert payload["selected_provider"] is None
