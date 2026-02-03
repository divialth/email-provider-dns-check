from provider_check.checker import RecordCheck
from provider_check.output import to_human


def test_to_human_renders_table():
    results = [
        RecordCheck("MX", "PASS", "ok", {"found": ["mx"]}),
        RecordCheck(
            "SPF",
            "WARN",
            "extra",
            {"record": "v=spf1 include:example.test ~all", "extras": ["include:other"]},
        ),
    ]

    table = to_human(results, "example.com", "2026-01-31 19:37", "dummy-provider", "9")

    lines = [line for line in table.splitlines() if line.strip()]
    assert (
        lines[0]
        == "WARN - report for domain example.com (2026-01-31 19:37) / provider: dummy-provider (v9)"
    )
    assert "MX - PASS: ok" in table
    assert "| Status" in table
    assert "| PASS" in table
    assert "SPF - WARN: extra" in table
    assert "include:other" in table


def test_to_human_includes_dkim_selectors():
    selectors = {
        "SEL1._domainkey.example.com": "SEL1._domainkey.provider.test.",
        "SEL2._domainkey.example.com": "SEL2._domainkey.provider.test.",
    }
    results = [
        RecordCheck("DKIM", "PASS", "All DKIM selectors configured", {"selectors": selectors})
    ]

    table = to_human(results, "example.com", "2026-01-31 19:37", "dummy-provider", "9")

    assert "DKIM - PASS: All DKIM selectors configured" in table
    for selector in selectors:
        assert selector in table


def test_dkim_human_summary_details_blank():
    selectors = {
        "SEL1._domainkey.example.com": "SEL1._domainkey.provider.test.",
        "SEL2._domainkey.example.com": "SEL2._domainkey.provider.test.",
    }
    result = RecordCheck(
        "DKIM",
        "FAIL",
        "DKIM selectors not fully aligned",
        {
            "missing": ["SEL2._domainkey.example.com"],
            "mismatched": {},
            "expected_selectors": list(selectors.keys()),
            "found_selectors": ["SEL1._domainkey.example.com"],
            "expected_targets": selectors,
        },
    )

    table = to_human([result], "example.com", "2026-01-31 19:37", "dummy-provider", "9")
    lines = [line for line in table.splitlines() if line.strip()]
    summary_line = next(line for line in lines if line.startswith("DKIM -"))

    assert "expected_selectors" not in summary_line
    assert "missing" not in summary_line


def test_to_human_uses_custom_template(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    template_dir = tmp_path / "provider-dns-check" / "templates"
    template_dir.mkdir(parents=True)
    template = template_dir / "human.j2"
    template.write_text(
        "{{ build_table_rows(results)|length }}|{{ provider_label }}",
        encoding="utf-8",
    )

    results = [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]
    output = to_human(
        results,
        "example.com",
        "2026-01-31 19:37",
        "dummy-provider",
        "9",
    )

    assert output.startswith("1|dummy-provider (v9)")
