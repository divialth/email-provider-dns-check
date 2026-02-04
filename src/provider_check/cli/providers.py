"""Provider-related CLI handlers."""

from __future__ import annotations

from typing import Callable, Iterable, List

import yaml


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
