"""Provider auto-detection helpers."""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import Dict, Iterable, List, Optional, Sequence

from .checker import DNSChecker, RecordCheck
from .dns_resolver import DnsLookupError, DnsResolver
from .provider_config import ProviderConfig, list_providers, resolve_provider_config

LOGGER = logging.getLogger(__name__)

DEFAULT_TOP_N = 3
CORE_RECORD_TYPES = {"MX", "SPF", "DKIM", "CNAME", "SRV"}
TYPE_WEIGHTS = {
    "MX": 5,
    "SPF": 4,
    "DKIM": 4,
    "CNAME": 3,
    "SRV": 2,
    "TXT": 1,
    "DMARC": 1,
}
STATUS_SCORES = {"PASS": 2, "WARN": 1, "FAIL": 0, "UNKNOWN": 0}
_TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


@dataclasses.dataclass(frozen=True)
class DetectionCandidate:
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


@dataclasses.dataclass(frozen=True)
class DetectionReport:
    domain: str
    candidates: List[DetectionCandidate]
    selected: Optional[DetectionCandidate]
    ambiguous: bool
    status: str
    top_n: int = DEFAULT_TOP_N


def _normalize_host(host: str) -> str:
    return host.rstrip(".").lower() + "."


def _normalize_host_template(template: str) -> str:
    trimmed = template.strip()
    if not trimmed.endswith("."):
        trimmed = trimmed + "."
    return trimmed


def _normalize_record_name(name: str, domain: str) -> str:
    trimmed = name.strip()
    if trimmed == "@":
        return domain.lower()
    if "{domain}" in trimmed:
        trimmed = trimmed.replace("{domain}", domain)
    if trimmed.endswith("."):
        return trimmed[:-1].lower()
    trimmed_lower = trimmed.lower()
    domain_lower = domain.lower()
    if trimmed_lower.endswith(domain_lower):
        return trimmed_lower
    if "." in trimmed:
        return trimmed_lower
    return f"{trimmed_lower}.{domain_lower}"


def _template_regex(
    template: str, known_vars: Dict[str, str], capture_vars: Iterable[str]
) -> re.Pattern:
    capture_set = set(capture_vars)
    pattern = ""
    idx = 0
    for match in _TEMPLATE_RE.finditer(template):
        pattern += re.escape(template[idx : match.start()])
        var_name = match.group(1)
        if var_name in known_vars:
            pattern += re.escape(known_vars[var_name])
        elif var_name in capture_set:
            pattern += f"(?P<{var_name}>.+?)"
        else:
            pattern += ".+?"
        idx = match.end()
    pattern += re.escape(template[idx:])
    return re.compile(f"^{pattern}$", re.IGNORECASE)


def _match_and_infer(
    template: str,
    samples: Sequence[str],
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
    capture_vars: Iterable[str],
) -> None:
    if not samples:
        return
    regex = _template_regex(template, known_vars, capture_vars)
    for sample in samples:
        match = regex.match(sample)
        if not match:
            continue
        updates = {key: value for key, value in match.groupdict().items() if value is not None}
        if any(
            key in inferred_vars and inferred_vars[key] != value for key, value in updates.items()
        ):
            continue
        for key, value in updates.items():
            inferred_vars.setdefault(key, value)
        break


def _infer_from_mx(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    if not provider.mx:
        return
    try:
        mx_records = resolver.get_mx(domain)
    except DnsLookupError as err:
        LOGGER.debug("MX lookup failed during detection for %s: %s", domain, err)
        return
    samples = [_normalize_host(host) for host, _pref in mx_records]
    templates = [_normalize_host_template(host) for host in provider.mx.hosts]
    for template in templates:
        _match_and_infer(template, samples, known_vars, inferred_vars, provider.variables)


def _infer_from_dkim(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    if not provider.dkim or provider.dkim.record_type != "cname":
        return
    template = provider.dkim.target_template
    if not template:
        return
    for selector in provider.dkim.selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            target = resolver.get_cname(name)
        except DnsLookupError as err:
            LOGGER.debug("DKIM CNAME lookup failed during detection for %s: %s", name, err)
            continue
        if not target:
            continue
        selector_vars = dict(known_vars)
        selector_vars["selector"] = selector.lower()
        normalized_template = _normalize_host_template(template)
        normalized_target = _normalize_host(target)
        _match_and_infer(
            normalized_template,
            [normalized_target],
            selector_vars,
            inferred_vars,
            provider.variables,
        )


def _infer_from_cname(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    if not provider.cname:
        return
    for name, target_template in provider.cname.records.items():
        lookup_name = _normalize_record_name(name, domain)
        if "{" in lookup_name or "}" in lookup_name:
            continue
        try:
            target = resolver.get_cname(lookup_name)
        except DnsLookupError as err:
            LOGGER.debug("CNAME lookup failed during detection for %s: %s", lookup_name, err)
            continue
        if not target:
            continue
        normalized_template = _normalize_host_template(target_template)
        normalized_target = _normalize_host(target)
        _match_and_infer(
            normalized_template,
            [normalized_target],
            known_vars,
            inferred_vars,
            provider.variables,
        )


def _infer_from_srv(
    provider: ProviderConfig,
    domain: str,
    resolver: DnsResolver,
    known_vars: Dict[str, str],
    inferred_vars: Dict[str, str],
) -> None:
    if not provider.srv:
        return
    for name, entries in provider.srv.records.items():
        lookup_name = _normalize_record_name(name, domain)
        if "{" in lookup_name or "}" in lookup_name:
            continue
        try:
            found_entries = resolver.get_srv(lookup_name)
        except DnsLookupError as err:
            LOGGER.debug("SRV lookup failed during detection for %s: %s", lookup_name, err)
            continue
        targets = [_normalize_host(target) for _pri, _weight, _port, target in found_entries]
        for entry in entries:
            normalized_template = _normalize_host_template(entry.target)
            _match_and_infer(
                normalized_template,
                targets,
                known_vars,
                inferred_vars,
                provider.variables,
            )


def infer_provider_variables(
    provider: ProviderConfig, domain: str, resolver: DnsResolver
) -> Dict[str, str]:
    if not provider.variables:
        return {}
    known_vars = {"domain": domain.lower().strip()}
    inferred: Dict[str, str] = {}
    _infer_from_mx(provider, domain, resolver, known_vars, inferred)
    _infer_from_dkim(provider, domain, resolver, known_vars, inferred)
    _infer_from_cname(provider, domain, resolver, known_vars, inferred)
    _infer_from_srv(provider, domain, resolver, known_vars, inferred)
    return inferred


def _score_results(results: List[RecordCheck]) -> tuple[int, int, float, List[str], Dict[str, int]]:
    score = 0
    max_score = 0
    core_pass_records: List[str] = []
    status_counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0}
    for result in results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
        weight = TYPE_WEIGHTS.get(result.record_type, 1)
        max_score += weight * STATUS_SCORES["PASS"]
        score += weight * STATUS_SCORES.get(result.status, 0)
        if result.record_type in CORE_RECORD_TYPES and result.status == "PASS":
            core_pass_records.append(result.record_type)
    ratio = score / max_score if max_score else 0.0
    return score, max_score, ratio, core_pass_records, status_counts


def _same_ratio(left: DetectionCandidate, right: DetectionCandidate) -> bool:
    return left.score * right.max_score == right.score * left.max_score


def _same_score(left: DetectionCandidate, right: DetectionCandidate) -> bool:
    return left.score == right.score and left.max_score == right.max_score


def detect_providers(
    domain: str,
    *,
    resolver: Optional[DnsResolver] = None,
    top_n: int = DEFAULT_TOP_N,
) -> DetectionReport:
    normalized_domain = domain.lower().strip()
    resolver = resolver or DnsResolver()
    candidates: List[DetectionCandidate] = []
    for provider in list_providers():
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
        if not results:
            continue
        score, max_score, ratio, core_pass_records, status_counts = _score_results(results)
        if not core_pass_records:
            continue
        record_statuses = {result.record_type: result.status for result in results}
        candidates.append(
            DetectionCandidate(
                provider_id=provider.provider_id,
                provider_name=provider.name,
                provider_version=provider.version,
                inferred_variables=inferred_vars,
                score=score,
                max_score=max_score,
                score_ratio=ratio,
                status_counts=status_counts,
                record_statuses=record_statuses,
                core_pass_records=sorted(core_pass_records),
            )
        )

    candidates.sort(key=lambda item: (item.score_ratio, item.score, item.provider_id), reverse=True)
    top_candidates = candidates[: max(top_n, 0)]
    selected: Optional[DetectionCandidate] = None
    ambiguous = False
    if top_candidates:
        selected = top_candidates[0]
        if (
            len(top_candidates) > 1
            and _same_ratio(top_candidates[0], top_candidates[1])
            and _same_score(top_candidates[0], top_candidates[1])
        ):
            ambiguous = True
            selected = None
    status = "PASS" if selected and not ambiguous else "UNKNOWN"
    return DetectionReport(
        domain=normalized_domain,
        candidates=top_candidates,
        selected=selected,
        ambiguous=ambiguous,
        status=status,
        top_n=top_n,
    )
