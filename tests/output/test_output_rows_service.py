from provider_check.output import (
    _build_address_rows,
    _build_srv_rows,
    _build_tlsa_rows,
    _build_txt_rows,
)


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


def test_build_address_rows_supports_ptr_label():
    result = {
        "record_type": "PTR",
        "status": "PASS",
        "details": {"expected": {"10.2.0.192.in-addr.arpa": ["mail.example.test."]}},
    }

    rows = _build_address_rows(result)

    assert rows[0]["message"] == "PTR 10.2.0.192.in-addr.arpa"


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


def test_build_tlsa_rows_with_missing_and_extra():
    result = {
        "status": "FAIL",
        "details": {
            "expected": {"_25._tcp.mail.example.test": [(3, 1, 1, "aabb")]},
            "found": {"_25._tcp.mail.example.test": [(3, 1, 1, "ccdd")]},
            "missing": {"_25._tcp.mail.example.test": [(3, 1, 1, "aabb")]},
            "extra": {"_25._tcp.mail.example.test": [(3, 1, 1, "ccdd")]},
        },
    }

    rows = _build_tlsa_rows(result)

    assert any(row["found"] == "(missing)" for row in rows)
    assert any("TLSA _25._tcp.mail.example.test extra" == row["message"] for row in rows)


def test_build_tlsa_rows_pass_uses_expected_when_found_missing():
    result = {
        "status": "PASS",
        "details": {"expected": {"_25._tcp.mail.example.test": [(3, 1, 1, "aabb")]}},
    }

    rows = _build_tlsa_rows(result)

    assert rows[0]["found"].startswith("usage 3 selector 1 matching_type 1")


def test_build_tlsa_rows_marks_missing_without_missing_details():
    result = {
        "status": "FAIL",
        "details": {"expected": {"_25._tcp.mail.example.test": [(3, 1, 1, "aabb")]}},
    }

    rows = _build_tlsa_rows(result)

    assert rows[0]["status"] == "FAIL"
    assert rows[0]["found"] == "(missing)"


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
