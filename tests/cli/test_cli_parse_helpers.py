"""Tests for CLI parser helper functions."""

from __future__ import annotations

from argparse import ArgumentTypeError
import logging

import pytest

from provider_check.cli import (
    _parse_dmarc_pct,
    _parse_positive_float,
    _parse_positive_int,
    _parse_provider_vars,
    _parse_txt_records,
    _setup_logging,
)


def test_setup_logging_levels(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure INFO/DEBUG levels from verbosity settings."""
    captured: list[int] = []

    def _fake_basic_config(**kwargs):
        captured.append(kwargs.get("level"))

    monkeypatch.setattr(logging, "basicConfig", _fake_basic_config)

    _setup_logging(1)
    assert captured[-1] == logging.INFO

    _setup_logging(2)
    assert captured[-1] == logging.DEBUG


@pytest.mark.parametrize("raw", ["missing-delimiter", "=value", "name="])
def test_parse_txt_records_rejects_invalid(raw: str) -> None:
    """Reject invalid ``--txt`` entries."""
    with pytest.raises(ValueError):
        _parse_txt_records([raw])


@pytest.mark.parametrize("raw", ["missing-delimiter", "=value", "name=", "dup=1|dup=2"])
def test_parse_provider_vars_rejects_invalid(raw: str) -> None:
    """Reject invalid ``--provider-var`` entries."""
    values = raw.split("|")
    with pytest.raises(ValueError):
        _parse_provider_vars(values)


@pytest.mark.parametrize("raw", ["n/a", "101"])
def test_parse_dmarc_pct_rejects_invalid(raw: str) -> None:
    """Reject invalid DMARC percentage values."""
    with pytest.raises(ArgumentTypeError):
        _parse_dmarc_pct(raw)


@pytest.mark.parametrize("raw", ["n/a", "0"])
def test_parse_positive_float_rejects_invalid(raw: str) -> None:
    """Reject invalid positive float arguments."""
    with pytest.raises(ArgumentTypeError):
        _parse_positive_float(raw, label="DNS timeout")


def test_parse_positive_float_accepts_value() -> None:
    """Parse valid positive float values."""
    assert _parse_positive_float("1.5", label="DNS timeout") == 1.5


@pytest.mark.parametrize("raw", ["n/a", "0"])
def test_parse_positive_int_rejects_invalid(raw: str) -> None:
    """Reject invalid positive integer arguments."""
    with pytest.raises(ArgumentTypeError):
        _parse_positive_int(raw, label="Provider detect limit")


def test_parse_positive_int_accepts_value() -> None:
    """Parse valid positive integer values."""
    assert _parse_positive_int("3", label="Provider detect limit") == 3
