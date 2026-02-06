from provider_check.checker import RecordCheck
from provider_check.output import _serialize_results


def test_serialize_results_builds_caa_missing_rows():
    result = RecordCheck.fail(
        "CAA",
        "Missing required CAA records",
        {
            "missing": {"example.com": [{"flags": 0, "tag": "issue", "value": "ca.example.test"}]},
            "expected": {"example.com": [{"flags": 0, "tag": "issue", "value": "ca.example.test"}]},
            "found": {"example.com": []},
        },
    )

    serialized = _serialize_results([result])
    rows = serialized[0]["rows"]

    assert any(row["message"] == "CAA example.com" for row in rows)
    assert any(row["found"] == "(missing)" for row in rows)


def test_serialize_results_builds_caa_pass_rows():
    result = RecordCheck.pass_(
        "CAA",
        "Required CAA records present",
        {"expected": {"example.com": [{"flags": 0, "tag": "issue", "value": "ca.example.test"}]}},
    )

    serialized = _serialize_results([result])
    rows = serialized[0]["rows"]

    assert rows[0]["expected"].startswith("flags 0 tag issue")
    assert rows[0]["found"].startswith("flags 0 tag issue")


def test_serialize_results_builds_caa_extra_rows():
    result = RecordCheck.fail(
        "CAA",
        "CAA records do not exactly match required configuration",
        {
            "expected": {"example.com": [{"flags": 0, "tag": "issue", "value": "ca.example.test"}]},
            "found": {"example.com": [{"flags": 0, "tag": "issue", "value": "ca.example.test"}]},
            "extra": {"example.com": [{"flags": 0, "tag": "issuewild", "value": "ca.example"}]},
        },
    )

    serialized = _serialize_results([result])
    rows = serialized[0]["rows"]

    assert any("extra" in row["message"] for row in rows)
