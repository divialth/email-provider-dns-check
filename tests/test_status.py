from provider_check import status


def test_exit_code_for_status_matches_exit_codes() -> None:
    assert status.exit_code_for_status(status.Status.PASS.value) == status.ExitCodes.PASS
    assert status.exit_code_for_status(status.Status.WARN.value) == status.ExitCodes.WARN
    assert status.exit_code_for_status(status.Status.FAIL.value) == status.ExitCodes.FAIL
    assert status.exit_code_for_status(status.Status.UNKNOWN.value) == status.ExitCodes.UNKNOWN


def test_exit_code_for_status_defaults_to_unknown() -> None:
    assert status.exit_code_for_status("NOT_A_STATUS") == status.ExitCodes.UNKNOWN
