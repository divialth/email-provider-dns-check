"""Shared fixtures for provider config tests."""

from __future__ import annotations

import logging
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from provider_check.provider_config import list_providers
from provider_check.provider_config import ProviderConfig


@pytest.fixture
def provider_dir(tmp_path: Path) -> Path:
    """Create a temporary provider directory.

    Args:
        tmp_path (Path): Base pytest temporary directory.

    Returns:
        Path: Directory where temporary provider YAML files can be written.
    """
    directory = tmp_path / "providers"
    directory.mkdir()
    return directory


@pytest.fixture
def write_provider_yaml(provider_dir: Path) -> Callable[[str, str], None]:
    """Build a helper that writes provider YAML in the temporary directory.

    Args:
        provider_dir (Path): Temporary provider directory fixture.

    Returns:
        Callable[[str, str], None]: Writer function that accepts YAML content
        and an optional provider ID.
    """

    def _write(content: str, provider_id: str = "bad") -> None:
        (provider_dir / f"{provider_id}.yaml").write_text(
            textwrap.dedent(content).strip(),
            encoding="utf-8",
        )

    return _write


@pytest.fixture
def list_providers_with_warnings(
    caplog: pytest.LogCaptureFixture,
    provider_dir: Path,
) -> Callable[[], tuple[list, list[str]]]:
    """List providers and collect warning log messages.

    Args:
        caplog (pytest.LogCaptureFixture): Log capture fixture.
        provider_dir (Path): Temporary provider directory fixture.

    Returns:
        Callable[[], tuple[list, list[str]]]: Runner function that returns
        loaded providers and warning messages emitted during loading.
    """

    def _run() -> tuple[list, list[str]]:
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            providers = list_providers(provider_dirs=[provider_dir])
        messages = [record.getMessage() for record in caplog.records]
        return providers, messages

    return _run


@pytest.fixture
def assert_provider_rejected(
    write_provider_yaml: Callable[[str, str], None],
    list_providers_with_warnings: Callable[[], tuple[list, list[str]]],
) -> Callable[[str, str], None]:
    """Build an assertion helper for rejected provider configs.

    Args:
        write_provider_yaml (Callable[[str, str], None]): Provider writer fixture.
        list_providers_with_warnings (Callable[[], tuple[list, list[str]]]): Provider
            listing helper with log capture.

    Returns:
        Callable[[str, str], None]: Assertion helper that accepts YAML content
        and expected warning text.
    """

    def _assert(content: str, expected_warning: str) -> None:
        write_provider_yaml(content, provider_id="bad")
        providers, messages = list_providers_with_warnings()
        provider_ids = {provider.provider_id for provider in providers}
        assert "bad" not in provider_ids
        assert any(expected_warning in message for message in messages), messages

    return _assert


@pytest.fixture
def assert_provider_accepted(
    write_provider_yaml: Callable[[str, str], None],
    list_providers_with_warnings: Callable[[], tuple[list, list[str]]],
) -> Callable[[str, str], None]:
    """Build an assertion helper for accepted provider configs.

    Args:
        write_provider_yaml (Callable[[str, str], None]): Provider writer fixture.
        list_providers_with_warnings (Callable[[], tuple[list, list[str]]]): Provider
            listing helper with log capture.

    Returns:
        Callable[[str, str], None]: Assertion helper that accepts YAML content
        and an optional provider ID.
    """

    def _assert(content: str, provider_id: str = "valid") -> None:
        write_provider_yaml(content, provider_id=provider_id)
        providers, _messages = list_providers_with_warnings()
        provider_ids = {provider.provider_id for provider in providers}
        assert provider_id in provider_ids

    return _assert


@pytest.fixture
def provider_config_loader():
    """Import the provider config loader module used by tests.

    Returns:
        module: Imported ``provider_check.provider_config.loader`` module.
    """
    import provider_check.provider_config.loader as provider_config

    return provider_config


@pytest.fixture
def make_provider_config() -> Callable[..., ProviderConfig]:
    """Build minimal provider config objects for loader tests.

    Returns:
        Callable[..., ProviderConfig]: Factory function for ``ProviderConfig``.
    """

    def _make(provider_id: str, name: str) -> ProviderConfig:
        return ProviderConfig(
            provider_id=provider_id,
            name=name,
            version="1",
            mx=None,
            spf=None,
            dkim=None,
            txt=None,
            dmarc=None,
        )

    return _make


@pytest.fixture
def fake_path_factory() -> Callable[[str, str], object]:
    """Build fake path-like objects exposing ``name`` and ``read_text``.

    Returns:
        Callable[[str, str], object]: Factory for fake path-like objects.
    """

    def _make(name: str, content: str) -> object:
        class _FakePath:
            def __init__(self, path_name: str, raw: str):
                self.name = path_name
                self._content = raw

            def read_text(self, encoding: str = "utf-8"):
                return self._content

        return _FakePath(name, content)

    return _make
