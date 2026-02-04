"""Formatting helpers for CLI output."""

from __future__ import annotations

from typing import Callable, List

from ..detection import DetectionReport


def _build_detection_payload(report: DetectionReport, report_time: str) -> dict:
    """Build a JSON-serializable payload from a detection report.

    Args:
        report (DetectionReport): Detection report data.
        report_time (str): UTC report timestamp string.

    Returns:
        dict: JSON-serializable payload.
    """
    candidates = []
    for candidate in report.candidates:
        candidates.append(
            {
                "provider_id": candidate.provider_id,
                "provider_name": candidate.provider_name,
                "provider_version": candidate.provider_version,
                "score": candidate.score,
                "max_score": candidate.max_score,
                "score_ratio": round(candidate.score_ratio, 4),
                "optional_bonus": candidate.optional_bonus,
                "status_counts": dict(candidate.status_counts),
                "record_statuses": dict(candidate.record_statuses),
                "core_pass_records": list(candidate.core_pass_records),
                "inferred_variables": dict(candidate.inferred_variables),
            }
        )
    selected_provider = None
    if report.selected:
        selected_provider = {
            "provider_id": report.selected.provider_id,
            "provider_name": report.selected.provider_name,
            "provider_version": report.selected.provider_version,
        }
    return {
        "domain": report.domain,
        "report_time_utc": report_time,
        "status": report.status,
        "top_n": report.top_n,
        "ambiguous": report.ambiguous,
        "selected_provider": selected_provider,
        "candidates": candidates,
    }


def _format_detection_report(
    report: DetectionReport,
    report_time: str,
    *,
    colorize_status: Callable[[str], str] | None = None,
) -> str:
    """Format a detection report as human-readable text.

    Args:
        report (DetectionReport): Detection report data.
        report_time (str): UTC report timestamp string.
        colorize_status (Callable[[str], str] | None): Status colorizer callback.

    Returns:
        str: Formatted detection report.
    """
    if colorize_status is None:
        colorize_status = lambda text: text
    lines = [
        f"{colorize_status(report.status)} - provider detection report for domain "
        f"{report.domain} ({report_time})"
    ]
    if report.selected:
        lines.append(
            "Selected provider: "
            f"{report.selected.provider_id} ({report.selected.provider_name} "
            f"v{report.selected.provider_version})"
        )
    elif report.ambiguous:
        lines.append("Top candidates are tied; unable to select provider.")
    else:
        lines.append("No matching providers detected.")

    if report.candidates:
        lines.append(f"Top {len(report.candidates)} candidates:")
        for idx, candidate in enumerate(report.candidates, start=1):
            if candidate.max_score:
                score_label = (
                    f"{candidate.score}/{candidate.max_score} ({candidate.score_ratio:.0%})"
                )
            else:
                score_label = "n/a"
            lines.append(
                f"{idx}. {candidate.provider_id} - {candidate.provider_name} "
                f"(v{candidate.provider_version}) score {score_label}"
            )
            details: List[str] = []
            if candidate.core_pass_records:
                details.append(f"core: {', '.join(candidate.core_pass_records)}")
            if candidate.record_statuses:
                record_summary = " ".join(
                    f"{key}={colorize_status(value)}"
                    for key, value in sorted(candidate.record_statuses.items())
                )
                details.append(f"records: {record_summary}")
            if candidate.optional_bonus:
                details.append(f"optional bonus: {candidate.optional_bonus}")
            if candidate.inferred_variables:
                vars_summary = ", ".join(
                    f"{key}={value}" for key, value in sorted(candidate.inferred_variables.items())
                )
                details.append(f"vars: {vars_summary}")
            if details:
                lines.append(f"  {' | '.join(details)}")
    return "\n".join(lines)
