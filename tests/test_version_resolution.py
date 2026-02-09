"""Version resolution regression tests."""

from __future__ import annotations

from pathlib import Path

import provider_check


def test_source_checkout_prefers_source_version() -> None:
    assert provider_check._is_source_checkout(Path(provider_check.__file__))
    assert provider_check.__version__ == "2.2.0"


def test_resolve_version_uses_metadata_outside_source_checkout(monkeypatch) -> None:
    monkeypatch.setattr(provider_check, "_is_source_checkout", lambda _path: False)
    monkeypatch.setattr(provider_check, "version", lambda _name: "9.9.9")

    assert provider_check._resolve_version() == "9.9.9"


def test_resolve_version_falls_back_when_metadata_missing(monkeypatch) -> None:
    monkeypatch.setattr(provider_check, "_is_source_checkout", lambda _path: False)

    def _raise(_name: str) -> str:
        raise provider_check.PackageNotFoundError

    monkeypatch.setattr(provider_check, "version", _raise)

    assert provider_check._resolve_version() == "2.2.0"
