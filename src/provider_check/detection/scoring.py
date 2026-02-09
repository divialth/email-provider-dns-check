"""Scoring helpers for provider detection."""

from __future__ import annotations

from typing import Dict, List

from ..checker import RecordCheck
from ..record_registry import CORE_RECORD_TYPES, TYPE_WEIGHTS
from ..status import Status
from .report import DetectionCandidate

STATUS_SCORES = {
    Status.PASS.value: 2,
    Status.WARN.value: 1,
    Status.FAIL.value: 0,
    Status.UNKNOWN.value: 0,
}


def _score_results(results: List[RecordCheck]) -> tuple[int, int, float, List[str], Dict[str, int]]:
    """Score results for detection ranking.

    Args:
        results (List[RecordCheck]): Record check results.

    Returns:
        tuple[int, int, float, List[str], Dict[str, int]]: Score, max score, ratio,
            list of core pass record types, and counts of each status.
    """
    score = 0
    max_score = 0
    status_counts = {
        Status.PASS.value: 0,
        Status.WARN.value: 0,
        Status.FAIL.value: 0,
        Status.UNKNOWN.value: 0,
    }
    core_pass_records: List[str] = []
    for result in results:
        status_value = result.status.value
        status_counts[status_value] = status_counts.get(status_value, 0) + 1
        weight = TYPE_WEIGHTS.get(result.record_type, 1)
        max_score += weight * STATUS_SCORES[Status.PASS.value]
        score += weight * STATUS_SCORES.get(status_value, 0)
        if (
            result.record_type in CORE_RECORD_TYPES
            and result.status is Status.PASS
            and result.scope == "required"
        ):
            core_pass_records.append(result.record_type)
    ratio = score / max_score if max_score else 0
    return score, max_score, ratio, core_pass_records, status_counts


def _optional_bonus(results: List[RecordCheck]) -> int:
    """Compute optional record bonus score.

    Args:
        results (List[RecordCheck]): Record check results.

    Returns:
        int: Optional bonus score.
    """
    return sum(
        TYPE_WEIGHTS.get(result.record_type, 1)
        for result in results
        if result.status is Status.PASS
    )


def _same_ratio(left: DetectionCandidate, right: DetectionCandidate) -> bool:
    """Compare candidates by score ratio without floating point drift.

    Args:
        left (DetectionCandidate): First candidate.
        right (DetectionCandidate): Second candidate.

    Returns:
        bool: True if ratios are equal.
    """
    return left.score * right.max_score == right.score * left.max_score


def _same_score(left: DetectionCandidate, right: DetectionCandidate) -> bool:
    """Check whether two candidates have identical scores.

    Args:
        left (DetectionCandidate): First candidate.
        right (DetectionCandidate): Second candidate.

    Returns:
        bool: True if both score and max score match.
    """
    return left.score == right.score and left.max_score == right.max_score


def _same_optional_bonus(left: DetectionCandidate, right: DetectionCandidate) -> bool:
    """Check whether two candidates have identical optional bonuses.

    Args:
        left (DetectionCandidate): First candidate.
        right (DetectionCandidate): Second candidate.

    Returns:
        bool: True if both optional bonuses match.
    """
    return left.optional_bonus == right.optional_bonus
