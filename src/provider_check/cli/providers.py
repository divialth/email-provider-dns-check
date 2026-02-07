"""Provider-related CLI handlers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable, List, Literal

import yaml

from ..provider_config.loader.paths import _external_provider_dirs, _iter_provider_paths_in_dir
from ..provider_config.schema_validation import collect_provider_schema_errors


def _collect_provider_validation_results(
    provider_dirs: List[Path],
) -> list[dict[str, object]]:
    """Validate external/custom provider files and collect result data.

    Args:
        provider_dirs (List[Path]): Additional provider directories from CLI.

    Returns:
        list[dict[str, object]]: Per-file validation outcomes.
    """
    paths: List[Path] = []
    for directory in _external_provider_dirs(provider_dirs):
        paths.extend(list(_iter_provider_paths_in_dir(directory)))

    results: list[dict[str, object]] = []
    for path in paths:
        file_path = str(path)
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive
            results.append(
                {
                    "path": file_path,
                    "valid": False,
                    "errors": [{"location": "<root>", "message": f"failed to read YAML: {exc}"}],
                }
            )
            continue

        errors = collect_provider_schema_errors(payload)
        if errors:
            results.append({"path": file_path, "valid": False, "errors": errors})
            continue
        results.append({"path": file_path, "valid": True, "errors": []})
    return results


def _render_provider_validation_text(results: list[dict[str, object]]) -> None:
    """Render provider validation results as text/human output.

    Args:
        results (list[dict[str, object]]): Per-file validation outcomes.
    """
    if not results:
        print("No external/custom provider YAML files found.")
        return

    failed = 0
    for item in results:
        path = str(item["path"])
        valid = bool(item["valid"])
        errors = list(item["errors"])
        if valid:
            print(f"PASS {path}")
            continue
        failed += 1
        print(f"FAIL {path}")
        for err in errors:
            print(f"  - {path}:{err['location']}: {err['message']}")

    checked = len(results)
    if failed:
        print(f"Schema validation failed: {failed}/{checked} provider file(s) invalid.")
        return
    print(f"Schema validation passed: {checked}/{checked} provider file(s) valid.")


def _render_provider_validation_json(results: list[dict[str, object]]) -> None:
    """Render provider validation results as JSON.

    Args:
        results (list[dict[str, object]]): Per-file validation outcomes.
    """
    checked = len(results)
    failed = sum(1 for item in results if not bool(item["valid"]))
    payload: dict[str, object] = {
        "mode": "providers_validate",
        "checked": checked,
        "passed": checked - failed,
        "failed": failed,
        "valid": failed == 0,
        "results": results,
    }
    if checked == 0:
        payload["message"] = "No external/custom provider YAML files found."
    print(json.dumps(payload, sort_keys=True))


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


def handle_providers_validate(
    provider_dirs: List[Path],
    output_format: Literal["text", "json", "human"] = "human",
) -> int:
    """Handle the --providers-validate CLI command.

    Args:
        provider_dirs (List[Path]): Additional provider directories from CLI.
        output_format (Literal["text", "json", "human"]): CLI output format.

    Returns:
        int: Exit code (0 when all provider files pass, 2 when any fail).
    """
    results = _collect_provider_validation_results(provider_dirs)
    if output_format == "json":
        _render_provider_validation_json(results)
    else:
        _render_provider_validation_text(results)

    failed = sum(1 for item in results if not bool(item["valid"]))
    return 2 if failed else 0
