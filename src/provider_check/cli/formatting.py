"""Formatting helpers for CLI output."""

from __future__ import annotations

from typing import Callable

from ..detection import DetectionReport, build_detection_payload, format_detection_report


def _build_detection_payload(report: DetectionReport, report_time: str) -> dict:
    """Build a JSON-serializable payload from a detection report.

    Args:
        report (DetectionReport): Detection report data.
        report_time (str): UTC report timestamp string.

    Returns:
        dict: JSON-serializable payload.
    """
    return build_detection_payload(report, report_time)


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
    return format_detection_report(report, report_time, colorize_status=colorize_status)
