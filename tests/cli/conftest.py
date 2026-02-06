"""Shared fixtures for CLI tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest

from provider_check.checker import RecordCheck
from provider_check.detection import DetectionCandidate, DetectionReport
from provider_check.provider_config import ProviderConfig, ProviderVariable
from provider_check.status import Status


@pytest.fixture
def cli_module():
    """Load the CLI module under test.

    Returns:
        module: Imported ``provider_check.cli`` module.
    """
    import provider_check.cli as cli

    return cli


@pytest.fixture
def make_provider() -> Callable[..., ProviderConfig]:
    """Build a minimal provider configuration.

    Returns:
        Callable[..., ProviderConfig]: Factory for ``ProviderConfig`` instances.
    """

    def _make(
        *,
        provider_id: str = "dummy",
        name: str = "Dummy Provider",
        version: str = "1",
        variables: dict[str, ProviderVariable] | None = None,
    ) -> ProviderConfig:
        return ProviderConfig(
            provider_id=provider_id,
            name=name,
            version=version,
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
            variables=variables,
        )

    return _make


@pytest.fixture
def patch_cli_datetime(
    monkeypatch: pytest.MonkeyPatch,
    cli_module: Any,
) -> Callable[[datetime], None]:
    """Patch CLI time generation with a fixed datetime.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        cli_module (Any): Imported CLI module.

    Returns:
        Callable[[datetime], None]: Patch function that sets ``datetime.now``.
    """

    def _patch(now: datetime) -> None:
        fixed = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)

        class _FixedDateTime:
            @staticmethod
            def now(tz=None):
                return fixed

        monkeypatch.setattr(cli_module, "datetime", _FixedDateTime)

    return _patch


@pytest.fixture
def patch_provider_resolution(
    monkeypatch: pytest.MonkeyPatch,
    cli_module: Any,
) -> Callable[[ProviderConfig], None]:
    """Patch provider loading and resolution to return a static provider.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        cli_module (Any): Imported CLI module.

    Returns:
        Callable[[ProviderConfig], None]: Patch function.
    """

    def _patch(provider: ProviderConfig) -> None:
        monkeypatch.setattr(cli_module, "load_provider_config", lambda _selection: provider)
        monkeypatch.setattr(
            cli_module,
            "resolve_provider_config",
            lambda prov, *_args, **_kwargs: prov,
        )

    return _patch


@pytest.fixture
def patch_detection_report(
    monkeypatch: pytest.MonkeyPatch,
    cli_module: Any,
) -> Callable[[DetectionReport], None]:
    """Patch provider detection to return a fixed report.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        cli_module (Any): Imported CLI module.

    Returns:
        Callable[[DetectionReport], None]: Patch function.
    """

    def _patch(report: DetectionReport) -> None:
        monkeypatch.setattr(cli_module, "detect_providers", lambda *_args, **_kwargs: report)

    return _patch


@pytest.fixture
def patch_dns_checker(
    monkeypatch: pytest.MonkeyPatch,
    cli_module: Any,
) -> Callable[[list[RecordCheck]], None]:
    """Patch DNS checker to return prebuilt record checks.

    Args:
        monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch fixture.
        cli_module (Any): Imported CLI module.

    Returns:
        Callable[[list[RecordCheck]], None]: Patch function.
    """

    def _patch(results: list[RecordCheck]) -> None:
        class _DummyChecker:
            def run_checks(self):
                return list(results)

        monkeypatch.setattr(cli_module, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())

    return _patch


@pytest.fixture
def make_detection_candidate() -> Callable[..., DetectionCandidate]:
    """Build detection candidates used across CLI detection tests.

    Returns:
        Callable[..., DetectionCandidate]: Candidate factory.
    """

    def _make(
        *,
        provider_id: str = "dummy",
        inferred_variables: dict[str, str] | None = None,
        score: int = 10,
        max_score: int = 10,
        score_ratio: float = 1.0,
        status_counts: dict[str, int] | None = None,
        record_statuses: dict[str, str] | None = None,
        core_pass_records: list[str] | None = None,
        optional_bonus: int = 0,
    ) -> DetectionCandidate:
        return DetectionCandidate(
            provider_id=provider_id,
            provider_name="Dummy Provider",
            provider_version="1",
            inferred_variables=inferred_variables or {},
            score=score,
            max_score=max_score,
            score_ratio=score_ratio,
            status_counts=status_counts or {"PASS": 1, "WARN": 0, "FAIL": 0, "UNKNOWN": 0},
            record_statuses=record_statuses or {"MX": "PASS"},
            core_pass_records=core_pass_records or ["MX"],
            optional_bonus=optional_bonus,
        )

    return _make


@pytest.fixture
def make_detection_report() -> Callable[..., DetectionReport]:
    """Build detection reports used across CLI detection tests.

    Returns:
        Callable[..., DetectionReport]: Report factory.
    """

    def _make(
        candidate: DetectionCandidate | None,
        *,
        status: Status = Status.PASS,
        ambiguous: bool = False,
        selected: bool = True,
        top_n: int = 3,
    ) -> DetectionReport:
        candidates = [candidate] if candidate else []
        return DetectionReport(
            domain="example.com",
            candidates=candidates,
            selected=candidate if selected else None,
            ambiguous=ambiguous,
            status=status,
            top_n=top_n,
        )

    return _make
