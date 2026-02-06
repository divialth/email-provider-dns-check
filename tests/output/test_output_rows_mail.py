from provider_check.output import (
    _build_cname_rows,
    _build_dkim_rows,
    _build_dmarc_rows,
    _build_mx_rows,
    _build_spf_rows,
)


def test_build_dkim_rows_handles_missing_and_mismatch_and_present():
    result = {
        "details": {
            "missing": ["s1._domainkey.example.test"],
            "mismatched": {"s2._domainkey.example.test": "wrong.target."},
            "expected_targets": {
                "s1._domainkey.example.test": "expected.target.",
                "s2._domainkey.example.test": "expected.target.",
            },
        },
        "selector_rows": [
            {"name": "s1._domainkey.example.test", "status": "WARN", "message": "", "value": None},
            {"name": "s2._domainkey.example.test", "status": "WARN", "message": "", "value": None},
            {"name": "s3._domainkey.example.test", "status": "PASS", "message": "", "value": None},
        ],
    }

    rows = _build_dkim_rows(result)

    assert rows[0]["found"] == "(missing)"
    assert rows[1]["found"] == "wrong.target."
    assert rows[2]["expected"] == "present"


def test_build_mx_rows_handles_missing_mismatch_and_extra():
    result = {
        "status": "WARN",
        "details": {
            "found": ["mx1.example.test", "mx2.example.test"],
            "missing": ["mx3.example.test"],
            "extra": ["mx2.example.test"],
            "mismatched": {"mx1.example.test": {"expected": 10, "found": [0, 5]}},
        },
    }

    rows = _build_mx_rows(result)

    assert any(row["expected"] == "priority 10" for row in rows)
    assert any(row["found"] == "(missing)" for row in rows)
    assert any(row["message"].startswith("MX extra host") for row in rows)


def test_build_mx_rows_derives_expected_from_extra():
    result = {
        "status": "WARN",
        "details": {
            "found": ["mx1.example.test", "mx2.example.test"],
            "extra": ["mx2.example.test"],
        },
    }

    rows = _build_mx_rows(result)

    assert any(row["message"] == "MX host mx1.example.test" for row in rows)
    assert any(row["message"] == "MX extra host mx2.example.test" for row in rows)


def test_build_mx_rows_marks_missing_when_only_expected():
    result = {"status": "FAIL", "details": {"expected": ["mx1.example.test"]}}

    rows = _build_mx_rows(result)

    assert rows[0]["found"] == "(missing)"


def test_build_spf_rows_multiple_records():
    result = {
        "status": "FAIL",
        "details": {"found": ["v=spf1 -all", "v=spf1 ~all"]},
    }

    rows = _build_spf_rows(result)

    assert rows[0]["expected"] == "single SPF record"


def test_build_spf_rows_missing_record():
    result = {"status": "FAIL", "details": {"expected": "v=spf1 -all"}}

    rows = _build_spf_rows(result)

    assert rows[0]["found"] == "(missing)"


def test_build_spf_rows_single_record_expected_dash():
    result = {"status": "WARN", "details": {"found": ["v=spf1 -all"]}}

    rows = _build_spf_rows(result)

    assert rows[0]["expected"] == "-"


def test_build_cname_rows_missing_mismatch_and_found():
    result = {
        "status": "FAIL",
        "details": {
            "expected": {
                "a.example.test": "a.target.",
                "b.example.test": "b.target.",
                "c.example.test": "c.target.",
            },
            "found": {"c.example.test": "c.target."},
            "missing": ["a.example.test"],
            "mismatched": {"b.example.test": "wrong.target."},
        },
    }

    rows = _build_cname_rows(result)

    assert any(row["found"] == "(missing)" for row in rows)
    assert any(row["found"] == "wrong.target." for row in rows)
    assert any(row["found"] == "c.target." for row in rows)


def test_build_dmarc_rows_variants():
    record_result = {"status": "PASS", "details": {"record": "v=DMARC1; p=none"}}
    missing_result = {"status": "FAIL", "details": {"expected": "v=DMARC1; p=reject"}}
    found_result = {
        "status": "FAIL",
        "details": {"expected": "v=DMARC1; p=reject", "found": ["v=DMARC1; p=none"]},
    }

    record_rows = _build_dmarc_rows(record_result)
    missing_rows = _build_dmarc_rows(missing_result)
    found_rows = _build_dmarc_rows(found_result)

    assert record_rows[0]["found"] == "v=DMARC1; p=none"
    assert missing_rows[0]["found"] == "(missing)"
    assert "v=DMARC1; p=none" in found_rows[0]["found"]
