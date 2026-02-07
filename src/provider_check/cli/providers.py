"""Provider-related CLI handlers."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Callable, Iterable, List

import yaml
from jsonschema import Draft202012Validator

from ..provider_config.loader.paths import _external_provider_dirs, _iter_provider_paths_in_dir


def _load_provider_schema_validator() -> Draft202012Validator:
    """Load the provider JSON Schema validator.

    Returns:
        Draft202012Validator: Validator instance for provider YAML structures.
    """
    schema_text = (
        resources.files("provider_check.resources.providers")
        .joinpath("provider.schema.json")
        .read_text(encoding="utf-8")
    )
    schema = json.loads(schema_text)
    return Draft202012Validator(schema)


def _render_schema_error(path: Path, err: object) -> str:
    """Render a schema validation error for display.

    Args:
        path (Path): Provider file path.
        err (object): jsonschema ValidationError-like object.

    Returns:
        str: Human-readable error line.
    """
    location = ".".join(str(part) for part in err.absolute_path) or "<root>"
    return f"  - {path}:{location}: {err.message}"


def handle_providers_list(list_providers: Callable[[], Iterable[object]]) -> int:
    """Handle the --providers-list CLI command.

    Args:
        list_providers (Callable[[], Iterable[object]]): Provider listing callback.

    Returns:
        int: Exit code.
    """
    providers = list(list_providers())
    min_id_width = 24
    min_version_width = 6
    if providers:
        id_width = max(min_id_width, max(len(provider.provider_id) for provider in providers))
        version_width = max(
            min_version_width,
            max(len(f"v{provider.version}") for provider in providers),
        )
    else:
        id_width = min_id_width
        version_width = min_version_width
    for provider in providers:
        version_label = f"v{provider.version}"
        print(
            f"{provider.provider_id.ljust(id_width)}  "
            f"{version_label.ljust(version_width)}  {provider.name}"
        )
    return 0


def handle_provider_show(
    selection: str,
    parser: object,
    *,
    load_provider_config_data: Callable[[str], tuple[object, dict]],
    literal_string_cls: type,
    provider_show_dumper: type,
    strip_long_description_indicator: Callable[[str], str],
) -> int:
    """Handle the --provider-show CLI command.

    Args:
        selection (str): Provider ID or name.
        parser (object): Argument parser with an error() method.
        load_provider_config_data (Callable[[str], tuple[object, dict]]): Loader callback.
        literal_string_cls (type): YAML literal string wrapper.
        provider_show_dumper (type): YAML dumper class.
        strip_long_description_indicator (Callable[[str], str]): Output sanitizer.

    Returns:
        int: Exit code.
    """
    try:
        _, data = load_provider_config_data(selection)
    except ValueError as exc:
        parser.error(str(exc))
    if isinstance(data.get("long_description"), str):
        data = dict(data)
        data["long_description"] = literal_string_cls(data["long_description"])
    rendered = yaml.dump(
        data,
        Dumper=provider_show_dumper,
        sort_keys=False,
        width=10**9,
        default_flow_style=False,
    )
    print(strip_long_description_indicator(rendered))
    return 0


def handle_providers_validate(provider_dirs: List[Path]) -> int:
    """Handle the --providers-validate CLI command.

    Args:
        provider_dirs (List[Path]): Additional provider directories from CLI.

    Returns:
        int: Exit code (0 when all provider files pass, 2 when any fail).
    """
    validator = _load_provider_schema_validator()
    paths: List[Path] = []
    for directory in _external_provider_dirs(provider_dirs):
        paths.extend(list(_iter_provider_paths_in_dir(directory)))
    if not paths:
        print("No external/custom provider YAML files found.")
        return 0

    failed = 0
    for path in paths:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive
            failed += 1
            print(f"FAIL {path}")
            print(f"  - {path}:<root>: failed to read YAML: {exc}")
            continue

        errors = list(validator.iter_errors(payload))
        if not errors:
            print(f"PASS {path}")
            continue

        failed += 1
        print(f"FAIL {path}")
        for err in errors:
            print(_render_schema_error(path, err))

    checked = len(paths)
    if failed:
        print(f"Schema validation failed: {failed}/{checked} provider file(s) invalid.")
        return 2
    print(f"Schema validation passed: {checked}/{checked} provider file(s) valid.")
    return 0
