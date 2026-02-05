from provider_check import status


def test_exit_code_for_status_matches_exit_codes() -> None:
    assert status.exit_code_for_status(status.Status.PASS) == status.ExitCodes.PASS
    assert status.exit_code_for_status(status.Status.WARN) == status.ExitCodes.WARN
    assert status.exit_code_for_status(status.Status.FAIL) == status.ExitCodes.FAIL
    assert status.exit_code_for_status(status.Status.UNKNOWN) == status.ExitCodes.UNKNOWN


def test_exit_code_for_status_defaults_to_unknown() -> None:
    assert status.exit_code_for_status("NOT_A_STATUS") == status.ExitCodes.UNKNOWN


def test_coerce_status_handles_enum_and_string() -> None:
    assert status.coerce_status(status.Status.PASS) is status.Status.PASS
    assert status.coerce_status("WARN") is status.Status.WARN
    assert status.coerce_status("NOT_A_STATUS") is status.Status.UNKNOWN
