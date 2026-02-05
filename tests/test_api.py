from provider_check import api
from provider_check import runner


def test_api_exports_runner_objects() -> None:
    assert api.run_checks is runner.run_checks
    assert api.run_detection is runner.run_detection
    assert api.CheckRequest is runner.CheckRequest
    assert api.CheckResult is runner.CheckResult
    assert api.DetectionRequest is runner.DetectionRequest
    assert api.DetectionResult is runner.DetectionResult


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
        "list_providers",
        "load_provider_config",
        "resolve_provider_config",
    ):
        assert name in api.__all__
