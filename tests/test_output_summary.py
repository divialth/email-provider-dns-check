from provider_check.checker import RecordCheck
from provider_check.output import summarize_status
from provider_check.status import Status


def test_summarize_status():
    results = [
        RecordCheck.pass_("MX", "", {}),
        RecordCheck.warn("SPF", "", {}),
    ]

    assert summarize_status(results) is Status.WARN

    results[1].status = Status.FAIL
    assert summarize_status(results) is Status.FAIL

    results[1].status = Status.UNKNOWN
    assert summarize_status(results) is Status.UNKNOWN
