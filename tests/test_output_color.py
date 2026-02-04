from provider_check.checker import RecordCheck
from provider_check.output import (
    make_status_colorizer,
    resolve_color_enabled,
    strip_ansi,
    to_human,
    to_text,
)


class _FakeStream:
    def __init__(self, isatty: bool) -> None:
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


def test_make_status_colorizer_enabled():
    colorize = make_status_colorizer(True)

    colored = colorize("PASS")

    assert "\x1b[" in colored
    assert strip_ansi(colored) == "PASS"
    assert colorize("Status") == "Status"


def test_make_status_colorizer_disabled():
    colorize = make_status_colorizer(False)

    assert colorize("FAIL") == "FAIL"


def test_resolve_color_enabled_no_color_overrides_always():
    stream = _FakeStream(isatty=True)
    env = {"NO_COLOR": "1", "TERM": "xterm-256color"}

    assert resolve_color_enabled("always", stream, env) is False


def test_resolve_color_enabled_auto_respects_tty_and_term():
    stream = _FakeStream(isatty=True)

    assert resolve_color_enabled("auto", stream, {"TERM": "xterm-256color"}) is True
    assert resolve_color_enabled("auto", stream, {"TERM": "dumb"}) is False
    assert resolve_color_enabled("auto", _FakeStream(isatty=False), {"TERM": "xterm-256color"}) is (
        False
    )


def test_resolve_color_enabled_never_mode():
    stream = _FakeStream(isatty=True)

    assert resolve_color_enabled("never", stream, {"TERM": "xterm-256color"}) is False


def test_resolve_color_enabled_clicolor_zero_disables():
    stream = _FakeStream(isatty=True)

    assert resolve_color_enabled("auto", stream, {"TERM": "xterm-256color", "CLICOLOR": "0"}) is (
        False
    )


def test_resolve_color_enabled_force_color_enables():
    stream = _FakeStream(isatty=False)

    assert resolve_color_enabled("auto", stream, {"FORCE_COLOR": "1"}) is True


def test_resolve_color_enabled_force_color_zero_disables():
    stream = _FakeStream(isatty=True)

    assert resolve_color_enabled("auto", stream, {"FORCE_COLOR": "0"}) is False


def test_resolve_color_enabled_force_color_empty_enables():
    stream = _FakeStream(isatty=False)

    assert resolve_color_enabled("auto", stream, {"FORCE_COLOR": ""}) is True


def test_resolve_color_enabled_force_color_none_disables():
    stream = _FakeStream(isatty=True)

    assert resolve_color_enabled("auto", stream, {"FORCE_COLOR": None}) is False


def test_resolve_color_enabled_requires_isatty():
    assert resolve_color_enabled("auto", object(), {"TERM": "xterm-256color"}) is False


def test_to_text_applies_colorizer():
    result = RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})
    colorize = make_status_colorizer(True)

    text = to_text(
        [result],
        "example.com",
        "2026-01-31 19:37",
        "dummy-provider",
        "9",
        colorize_status=colorize,
    )

    assert "\x1b[" in text
    assert "PASS" in strip_ansi(text)


def test_to_human_applies_colorizer():
    result = RecordCheck("MX", "WARN", "warn", {"found": ["mx"]})
    colorize = make_status_colorizer(True)

    text = to_human(
        [result],
        "example.com",
        "2026-01-31 19:37",
        "dummy-provider",
        "9",
        colorize_status=colorize,
    )

    assert "\x1b[" in text
    assert "WARN" in strip_ansi(text)
