from provider_check.output import (
    _build_generic_rows,
    _build_result_rows,
    _build_table_rows,
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
    ptr_result = {
        "record_type": "PTR",
        "status": "PASS",
        "details": {"expected": {"10.2.0.192.in-addr.arpa": ["mail.example.test."]}},
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
    assert _build_result_rows(ptr_result)
    assert _build_result_rows(txt_result)
    assert _build_result_rows(dmarc_result)


def test_stringify_details_non_empty():
    assert _stringify_details({"key": "value"}) == '{"key":"value"}'
