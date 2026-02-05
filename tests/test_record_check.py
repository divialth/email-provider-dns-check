from provider_check.checker import RecordCheck
from provider_check.status import Status


def test_record_check_coerces_status_string() -> None:
    result = RecordCheck("MX", "PASS", "ok", {})
    assert result.status is Status.PASS
