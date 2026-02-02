import json

from provider_check.checker import RecordCheck
from provider_check.output import to_json


def test_to_json_includes_provider_and_domain():
    results = [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    payload = json.loads(to_json(results, "example.com", "2026-01-31 19:37", "dummy-provider", "9"))

    assert payload["domain"] == "example.com"
    assert payload["provider"] == "dummy-provider"
    assert payload["provider_config_version"] == "9"
    assert payload["report_time_utc"] == "2026-01-31 19:37"
    assert payload["results"][0]["record_type"] == "MX"
    assert payload["results"][0]["optional"] is False
