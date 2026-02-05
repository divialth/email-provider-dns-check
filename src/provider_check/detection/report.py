"""Detection report dataclasses."""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

from ..status import Status

DEFAULT_TOP_N = 3


@dataclasses.dataclass(frozen=True)
class DetectionCandidate:
    """Represent a provider match candidate during detection.

    Attributes:
        provider_id (str): Provider identifier.
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.
        inferred_variables (Dict[str, str]): Variables inferred from DNS records.
        score (int): Weighted score achieved by the candidate.
        max_score (int): Maximum possible score for the candidate.
        score_ratio (float): Score divided by maximum score.
        status_counts (Dict[str, int]): Counts of PASS/WARN/FAIL/UNKNOWN statuses.
        record_statuses (Dict[str, str]): Status per record type.
        core_pass_records (List[str]): Core record types that passed.
        optional_bonus (int): Optional record bonus used as a tie-breaker.
    """

    provider_id: str
    provider_name: str
    provider_version: str
    inferred_variables: Dict[str, str]
    score: int
    max_score: int
    score_ratio: float
    status_counts: Dict[str, int]
    record_statuses: Dict[str, str]
    core_pass_records: List[str]
    optional_bonus: int = 0


@dataclasses.dataclass(frozen=True)
class DetectionReport:
    """Summarize provider detection results for a domain.

    Attributes:
        domain (str): Domain that was checked.
        candidates (List[DetectionCandidate]): Top candidate matches.
        selected (Optional[DetectionCandidate]): Selected provider if unambiguous.
        ambiguous (bool): Whether the top candidates are tied.
        status (Status): Overall detection status.
        top_n (int): Number of candidates requested.
    """

    domain: str
    candidates: List[DetectionCandidate]
    selected: Optional[DetectionCandidate]
    ambiguous: bool
    status: Status
    top_n: int = DEFAULT_TOP_N
