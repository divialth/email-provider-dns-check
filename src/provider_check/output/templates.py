"""Template loading and rendering for output formats."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from ..provider_config import TEMPLATE_DIR_NAME, external_config_dirs

_TEMPLATE_PACKAGE = "provider_check.resources.templates"

_ENV = SandboxedEnvironment(autoescape=False, trim_blocks=True, lstrip_blocks=True)


def _provider_label(provider_name: str, provider_version: str) -> str:
    """Build a display label for a provider.

    Args:
        provider_name (str): Provider display name.
        provider_version (str): Provider configuration version.

    Returns:
        str: Label including provider name and version.
    """
    return f"{provider_name} (v{provider_version})"


def _find_template_path(template_name: str) -> Optional[Path]:
    """Find an external template override path.

    Args:
        template_name (str): Template filename to locate.

    Returns:
        Optional[Path]: Path to override template if found.
    """
    for base_dir in external_config_dirs():
        candidate = base_dir / TEMPLATE_DIR_NAME / template_name
        if candidate.is_file():
            return candidate
    return None


def _render_template(template_name: str, context: dict) -> str:
    """Render a template with the provided context.

    Args:
        template_name (str): Template filename to render.
        context (dict): Render context.

    Returns:
        str: Rendered template output.
    """
    override_path = _find_template_path(template_name)
    if override_path:
        source = override_path.read_text(encoding="utf-8")
    else:
        source = (
            resources.files(_TEMPLATE_PACKAGE).joinpath(template_name).read_text(encoding="utf-8")
        )
    return _ENV.from_string(source).render(**context)
