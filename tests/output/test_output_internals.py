from provider_check.checker import RecordCheck
from provider_check.output import _build_table_rows, _serialize_results, _stringify_details


def test_serialize_results_marks_mismatched_dkim():
    result = RecordCheck.warn(
        "DKIM",
        "DKIM selectors not fully aligned",
        {
            "missing": [],
            "mismatched": {"s1._domainkey.example.com": "wrong.target."},
            "expected_selectors": ["s1._domainkey.example.com"],
            "found_selectors": ["s1._domainkey.example.com"],
            "expected_targets": {"s1._domainkey.example.com": "target."},
        },
    )

    serialized = _serialize_results([result])
    selector_row = serialized[0]["selector_rows"][0]

    assert selector_row["status"] == "WARN"
    assert selector_row["details"]["found"] == "wrong.target."


def test_build_table_rows_includes_dkim_and_mx_rows():
    results = [
        RecordCheck.pass_(
            "DKIM",
            "All DKIM selectors configured",
            {"selectors": {"s1._domainkey.example.com": "target."}},
        ),
        RecordCheck.pass_("MX", "ok", {"found": ["mx"]}),
    ]

    serialized = _serialize_results(results)
    rows = _build_table_rows(serialized)

    assert any("DKIM selector s1._domainkey.example.com" in row[1] for row in rows)
    assert any(row[1].startswith("MX host") for row in rows)


def test_stringify_details_empty_returns_dash():
    assert _stringify_details({}) == "-"
