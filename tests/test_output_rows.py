from provider_check.output import (
    _build_address_rows,
    _build_cname_rows,
    _build_dkim_rows,
    _build_dmarc_rows,
    _build_generic_rows,
    _build_mx_rows,
    _build_result_rows,
    _build_spf_rows,
    _build_srv_rows,
    _build_table_rows,
    _build_txt_rows,
    _format_priority,
    _format_srv_entry,
    _stringify_details,
    _stringify_value,
)


def test_output_helper_formatters():
    assert _stringify_value(None) == "-"
    assert _stringify_value(["a", "b"]) == "a, b"
    assert _stringify_value(("a", "b")) == "a, b"
    assert _stringify_value("value") == "value"
    assert _format_priority(None) == "-"
    assert _format_priority([]) == "-"
    assert _format_priority([10]) == "priority 10"
    assert _format_priority([10, 20]) == "priorities 10, 20"
    assert _format_priority(5) == "priority 5"
    assert (
        _format_srv_entry((0, 1, 2, "srv.example.test"))
        == "priority 0 weight 1 port 2 target srv.example.test"
    )


def test_build_table_rows_falls_back_without_table_rows():
    results = [
        {
            "record_type": "UNKNOWN",
            "status": "UNKNOWN",
            "message": "oops",
            "details": {"error": "boom"},
            "optional": False,
            "selectors": {},
            "selector_rows": [],
        }
    ]

    rows = _build_table_rows(results)

    assert rows == [["UNKNOWN", "Error", "-", "boom"]]


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


def test_build_address_rows_missing_and_extra():
    result_extra = {
        "record_type": "A",
        "status": "WARN",
        "details": {
            "expected": {"mail.example.test": ["192.0.2.1"]},
            "found": {"mail.example.test": ["192.0.2.1", "192.0.2.2"]},
            "extra": {"mail.example.test": ["192.0.2.2"]},
        },
    }
    result_missing = {
        "record_type": "AAAA",
        "status": "FAIL",
        "details": {
            "expected": {"mail.example.test": ["2001:db8::1"]},
            "missing": {"mail.example.test": ["2001:db8::1"]},
        },
    }

    extra_rows = _build_address_rows(result_extra)
    missing_rows = _build_address_rows(result_missing)

    assert any(row["expected"] == "(none)" for row in extra_rows)
    assert any(row["found"] == "(missing)" for row in missing_rows)


def test_build_address_rows_without_missing_details():
    result = {
        "record_type": "A",
        "status": "FAIL",
        "details": {"expected": {"mail.example.test": ["192.0.2.1"]}},
    }

    rows = _build_address_rows(result)

    assert rows[0]["found"] == "(missing)"


def test_build_srv_rows_with_missing_and_extra():
    result = {
        "status": "FAIL",
        "details": {
            "expected": {
                "_srv._tcp.example.test": [
                    (0, 5, 443, "target.example.test"),
                    (10, 0, 80, "alt.example.test"),
                ]
            },
            "found": {"_srv._tcp.example.test": [(0, 5, 443, "target.example.test")]},
            "missing": {"_srv._tcp.example.test": [(10, 0, 80, "alt.example.test")]},
            "extra": {"_srv._tcp.example.test": [(20, 0, 25, "extra.example.test")]},
        },
    }

    rows = _build_srv_rows(result)

    assert any(row["found"] == "(missing)" for row in rows)
    assert any("extra" in row["message"] for row in rows)


def test_build_srv_rows_pass_uses_expected_when_found_missing():
    result = {
        "status": "PASS",
        "details": {"expected": {"_srv._tcp.example.test": [(0, 5, 443, "srv.example.test")]}},
    }

    rows = _build_srv_rows(result)

    assert rows[0]["found"].startswith("priority 0 weight 5 port 443")


def test_build_srv_rows_with_mismatched_values():
    result = {
        "status": "WARN",
        "details": {
            "expected": {"_srv._tcp.example.test": [(10, 0, 443, "srv.example.test")]},
            "found": {"_srv._tcp.example.test": [(20, 5, 443, "srv.example.test")]},
            "mismatched": {
                "_srv._tcp.example.test": [
                    {
                        "expected": (10, 0, 443, "srv.example.test"),
                        "found": (20, 5, 443, "srv.example.test"),
                    }
                ]
            },
        },
    }

    rows = _build_srv_rows(result)

    assert any(row["found"].startswith("priority 20 weight 5 port 443") for row in rows)


def test_build_txt_rows_variants():
    missing_result = {
        "status": "FAIL",
        "details": {
            "missing": {"_verify.example.test": ["token"]},
            "missing_names": ["missing.example.test"],
            "verification_required": "user-supplied TXT verification value",
        },
    }
    required_dict_result = {
        "status": "PASS",
        "details": {"required": {"example.test": ["value1"]}},
    }
    required_scalar_result = {
        "status": "PASS",
        "details": {"required": {"example.test": "value2"}},
    }
    required_string_result = {
        "status": "WARN",
        "details": {"required": "verification token"},
    }
    empty_result = {"status": "PASS", "details": {}}

    missing_rows = _build_txt_rows(missing_result)
    required_rows = _build_txt_rows(required_dict_result)
    scalar_rows = _build_txt_rows(required_scalar_result)
    string_rows = _build_txt_rows(required_string_result)
    empty_rows = _build_txt_rows(empty_result)

    assert any(row["expected"] == "token" for row in missing_rows)
    assert any(row["message"] == "TXT verification required" for row in missing_rows)
    assert required_rows[0]["found"] == "value1"
    assert scalar_rows[0]["found"] == "value2"
    assert string_rows[0]["found"] == "(missing)"
    assert empty_rows[0]["expected"] == "(none)"


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


def test_build_generic_rows_variants():
    error_result = {"status": "UNKNOWN", "details": {"error": "boom"}}
    detail_result = {"status": "PASS", "details": {"note": "value"}}
    empty_result = {"status": "PASS", "details": {}}

    error_rows = _build_generic_rows(error_result)
    detail_rows = _build_generic_rows(detail_result)
    empty_rows = _build_generic_rows(empty_result)

    assert error_rows[0]["found"] == "boom"
    assert detail_rows[0]["expected"] == "value"
    assert empty_rows[0]["message"] == "No details"


def test_build_result_rows_falls_back_when_empty():
    result = {"record_type": "SPF", "status": "WARN", "details": {}}

    rows = _build_result_rows(result)

    assert rows[0]["message"] == "No details"


def test_build_result_rows_for_specific_record_types():
    cname_result = {
        "record_type": "CNAME",
        "status": "PASS",
        "details": {"expected": {"cname.example.test": "target.example.test."}},
    }
    a_result = {
        "record_type": "A",
        "status": "PASS",
        "details": {"expected": {"mail.example.test": ["192.0.2.1"]}},
    }
    srv_result = {
        "record_type": "SRV",
        "status": "PASS",
        "details": {"expected": {"_srv._tcp.example.test": [(0, 5, 443, "srv.example.test")]}},
    }
    txt_result = {
        "record_type": "TXT",
        "status": "PASS",
        "details": {"required": {"example.test": ["value"]}},
    }
    dmarc_result = {
        "record_type": "DMARC",
        "status": "PASS",
        "details": {"record": "v=DMARC1; p=none"},
    }

    assert _build_result_rows(cname_result)
    assert _build_result_rows(a_result)
    assert _build_result_rows(srv_result)
    assert _build_result_rows(txt_result)
    assert _build_result_rows(dmarc_result)


def test_stringify_details_non_empty():
    assert _stringify_details({"key": "value"}) == '{"key":"value"}'
