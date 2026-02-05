from provider_check import api
from provider_check import status
from provider_check import runner


def test_api_exports_runner_objects() -> None:
    assert api.run_checks is runner.run_checks
    assert api.run_detection is runner.run_detection
    assert api.CheckRequest is runner.CheckRequest
    assert api.CheckResult is runner.CheckResult
    assert api.DetectionRequest is runner.DetectionRequest
    assert api.DetectionResult is runner.DetectionResult
    assert api.ExitCodes is status.ExitCodes
    assert api.Status is status.Status
    assert api.coerce_status is status.coerce_status
    assert api.exit_code_for_status is status.exit_code_for_status


def test_api_all_exports() -> None:
    for name in (
        "run_checks",
        "run_detection",
        "CheckRequest",
        "CheckResult",
        "DetectionRequest",
        "DetectionResult",
        "DnsResolver",
        "CachingResolver",
        "DnsLookupError",
        "ProviderConfig",
        "ExitCodes",
        "Status",
        "coerce_status",
        "exit_code_for_status",
        "list_providers",
        "load_provider_config",
        "resolve_provider_config",
    ):
        assert name in api.__all__
