from provider_check.checker import RecordCheck
from provider_check.output import to_text


def test_to_text_lists_dkim_selectors():
    selectors = {"s1._domainkey.example.com": "s1._domainkey.provider.test."}
    result = RecordCheck.pass_("DKIM", "All DKIM selectors configured", {"selectors": selectors})

    text = to_text([result], "example.com", "2026-01-31 19:37", "dummy-provider", "9")

    assert (
        text.splitlines()[0]
        == "PASS - report for domain example.com (2026-01-31 19:37) / provider: dummy-provider (v9)"
    )
    assert "DKIM: PASS" in text
    assert "Status" in text
    assert "s1._domainkey.example.com" in text
    assert "s1._domainkey.provider.test." in text


def test_dkim_missing_still_lists_all_selectors():
    selectors = {
        "SEL1._domainkey.example.com": "SEL1._domainkey.provider.test.",
        "SEL2._domainkey.example.com": "SEL2._domainkey.provider.test.",
    }
    result = RecordCheck.fail(
        "DKIM",
        "DKIM selectors not fully aligned",
        {
            "missing": ["SEL2._domainkey.example.com"],
            "mismatched": {},
            "expected_selectors": list(selectors.keys()),
            "found_selectors": ["SEL1._domainkey.example.com"],
            "expected_targets": selectors,
        },
    )

    text = to_text([result], "example.com", "2026-01-31 19:37", "dummy-provider", "9")

    assert "SEL1._domainkey.example.com" in text
    assert "SEL2._domainkey.example.com" in text


def test_to_text_uses_custom_template(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    template_dir = tmp_path / "provider-dns-check" / "templates"
    template_dir.mkdir(parents=True)
    template = template_dir / "text.j2"
    template.write_text("{{ provider_label }}|{{ domain }}|{{ lines|length }}", encoding="utf-8")

    results = [RecordCheck.pass_("MX", "ok", {"found": ["mx"]})]
    output = to_text(
        results,
        "example.com",
        "2026-01-31 19:37",
        "dummy-provider",
        "9",
    )

    assert output == "dummy-provider (v9)|example.com|5"


def test_to_text_multiple_results_include_separator():
    results = [
        RecordCheck.pass_("MX", "ok", {"found": ["mx"]}),
        RecordCheck.pass_("SPF", "ok", {"record": "v=spf1 -all"}),
    ]

    text = to_text(results, "example.com", "2026-01-31 19:37", "dummy-provider", "9")

    assert "MX: PASS" in text
    assert "SPF: PASS" in text
