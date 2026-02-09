"""Provider auto-detection helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from ..checker import DNSChecker
from ..dns_resolver import CachingResolver, DnsResolver
from ..status import Status
from ..provider_config import ProviderConfig, list_providers, resolve_provider_config
from ..record_registry import CORE_RECORD_TYPES, TYPE_WEIGHTS
from .inference import (
    _infer_from_cname,
    _infer_from_dkim,
    _infer_from_mx,
    _infer_from_srv,
    infer_provider_variables,
)
from .formatting import build_detection_payload, format_detection_report
from .report import DEFAULT_TOP_N, DetectionCandidate, DetectionReport
from .scoring import (
    STATUS_SCORES,
    _optional_bonus,
    _same_optional_bonus,
    _same_ratio,
    _same_score,
    _score_results,
)
from .utils import (
    _match_and_infer,
    _normalize_host,
    _normalize_host_template,
    _normalize_record_name,
    _template_regex,
)

LOGGER = logging.getLogger(__name__)


def _result_status_key(result: object) -> str:
    """Build a detection status key for a result scope.

    Args:
        result (object): RecordCheck-like object.

    Returns:
        str: Status key including scope suffix when needed.
    """
    scope = getattr(result, "scope", "required")
    record_type = getattr(result, "record_type")
    if scope == "required":
        return str(record_type)
    if scope == "optional":
        return f"{record_type}_OPT"
    if scope == "deprecated":
        return f"{record_type}_DEP"
    if scope == "forbidden":
        return f"{record_type}_FORB"
    return f"{record_type}_{str(scope).upper()}"


__all__ = [
    "CORE_RECORD_TYPES",
    "DEFAULT_TOP_N",
    "DetectionCandidate",
    "DetectionReport",
    "STATUS_SCORES",
    "TYPE_WEIGHTS",
    "_infer_from_cname",
    "_infer_from_dkim",
    "_infer_from_mx",
    "_infer_from_srv",
    "_match_and_infer",
    "_normalize_host",
    "_normalize_host_template",
    "_normalize_record_name",
    "_optional_bonus",
    "_same_optional_bonus",
    "_same_ratio",
    "_same_score",
    "_score_results",
    "_template_regex",
    "build_detection_payload",
    "detect_providers",
    "format_detection_report",
    "infer_provider_variables",
]


def detect_providers(
    domain: str,
    *,
    resolver: Optional[DnsResolver] = None,
    top_n: int = DEFAULT_TOP_N,
    provider_dirs: Optional[List[Path | str]] = None,
) -> DetectionReport:
    """Detect provider candidates by running DNS checks.

    Args:
        domain (str): Domain to inspect.
        resolver (Optional[DnsResolver]): DNS resolver to use.
        top_n (int): Number of top candidates to return.
        provider_dirs (Optional[List[Path | str]]): Additional provider directories.

    Returns:
        DetectionReport: Detection report containing candidates and selection.
    """
    normalized_domain = domain.lower().strip()
    resolver = resolver or DnsResolver()
    if not isinstance(resolver, CachingResolver):
        resolver = CachingResolver(resolver)
    candidates: List[DetectionCandidate] = []
    providers = (
        list_providers() if provider_dirs is None else list_providers(provider_dirs=provider_dirs)
    )
    for provider in providers:
        inferred_vars = infer_provider_variables(provider, normalized_domain, resolver)
        try:
            resolved_provider = resolve_provider_config(
                provider, inferred_vars, domain=normalized_domain
            )
        except ValueError as exc:
            LOGGER.debug("Skipping provider %s: %s", provider.provider_id, exc)
            continue
        checker = DNSChecker(normalized_domain, resolved_provider, resolver=resolver, strict=False)
        results = checker.run_checks()
        scored_results = [
            result for result in results if result.scope in {"required", "deprecated", "forbidden"}
        ]
        optional_results = [result for result in results if result.scope == "optional"]
        if not scored_results:
            continue
        score, max_score, ratio, core_pass_records, status_counts = _score_results(scored_results)
        if not core_pass_records:
            continue
        optional_bonus = _optional_bonus(optional_results)
        record_statuses = {
            _result_status_key(result): result.status.value for result in scored_results
        }
        for result in optional_results:
            record_statuses[_result_status_key(result)] = result.status.value
            status_value = result.status.value
            status_counts[status_value] = status_counts.get(status_value, 0) + 1
        candidates.append(
            DetectionCandidate(
                provider_id=provider.provider_id,
                provider_name=provider.name,
                provider_version=provider.version,
                inferred_variables=inferred_vars,
                score=score,
                max_score=max_score,
                score_ratio=ratio,
                optional_bonus=optional_bonus,
                status_counts=status_counts,
                record_statuses=record_statuses,
                core_pass_records=sorted(core_pass_records),
            )
        )

    candidates.sort(
        key=lambda item: (item.score_ratio, item.score, item.optional_bonus, item.provider_id),
        reverse=True,
    )
    top_candidates = candidates[: max(top_n, 0)]
    selected: Optional[DetectionCandidate] = None
    ambiguous = False
    if top_candidates:
        selected = top_candidates[0]
        if (
            len(top_candidates) > 1
            and _same_ratio(top_candidates[0], top_candidates[1])
            and _same_score(top_candidates[0], top_candidates[1])
            and _same_optional_bonus(top_candidates[0], top_candidates[1])
        ):
            ambiguous = True
            selected = None
    status = Status.PASS if selected and not ambiguous else Status.UNKNOWN
    return DetectionReport(
        domain=normalized_domain,
        candidates=top_candidates,
        selected=selected,
        ambiguous=ambiguous,
        status=status,
        top_n=top_n,
    )
