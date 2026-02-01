from provider_check.checker import RecordCheck
from provider_check.output import summarize_status


def test_summarize_status():
    results = [
        RecordCheck("MX", "PASS", "", {}),
        RecordCheck("SPF", "WARN", "", {}),
    ]

    assert summarize_status(results) == "WARN"

    results[1].status = "FAIL"
    assert summarize_status(results) == "FAIL"

    results[1].status = "UNKNOWN"
    assert summarize_status(results) == "UNKNOWN"
