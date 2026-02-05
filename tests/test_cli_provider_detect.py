import json
from datetime import datetime, timezone

import pytest

from provider_check.checker import RecordCheck
from provider_check.detection import DetectionCandidate, DetectionReport
from provider_check.provider_config import ProviderConfig
from provider_check.cli import _build_detection_payload, _format_detection_report, main


def _patch_fixed_datetime(monkeypatch):
    class _FixedDateTime:
        @staticmethod
        def now(tz=None):
            return datetime(2026, 2, 2, 12, 0, tzinfo=timezone.utc)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "datetime", _FixedDateTime)


def _candidate(provider_id="dummy"):
    return DetectionCandidate(
        provider_id=provider_id,
        provider_name="Dummy Provider",
        provider_version="1",
        inferred_variables={},
        score=10,
        max_score=10,
        score_ratio=1.0,
        status_counts={"PASS": 1, "WARN": 0, "FAIL": 0, "UNKNOWN": 0},
        record_statuses={"MX": "PASS"},
        core_pass_records=["MX"],
    )


def _report(candidate=None, *, status="PASS", ambiguous=False, selected=True, top_n=3):
    candidates = [candidate] if candidate else []
    return DetectionReport(
        domain="example.com",
        candidates=candidates,
        selected=candidate if selected else None,
        ambiguous=ambiguous,
        status=status,
        top_n=top_n,
    )


def test_provider_detect_outputs_json(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)

    code = main(["example.com", "--provider-detect", "--output", "json"])
    assert code == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"
    assert payload["selected_provider"]["provider_id"] == "dummy"
    assert payload["candidates"][0]["provider_id"] == "dummy"


def test_provider_detect_limit_passed_to_detection(monkeypatch):
    candidate = _candidate()
    captured = {}

    def _fake_detect(_domain, *, resolver=None, top_n=None):
        captured["top_n"] = top_n
        return _report(candidate, top_n=top_n)

    import provider_check.cli as cli

    monkeypatch.setattr(cli, "detect_providers", _fake_detect)

    code = main(
        [
            "example.com",
            "--provider-detect",
            "--provider-detect-limit",
            "5",
            "--output",
            "json",
        ]
    )
    assert code == 0
    assert captured["top_n"] == 5


def test_format_detection_report_handles_empty_candidates():
    report = _report(None, status="UNKNOWN", ambiguous=False, selected=False)
    output = _format_detection_report(report, "2026-02-02 12:00")
    assert "No matching providers detected." in output


def test_format_detection_report_includes_vars_and_na_score():
    candidate = DetectionCandidate(
        provider_id="dummy",
        provider_name="Dummy Provider",
        provider_version="1",
        inferred_variables={"tenant": "acme"},
        score=0,
        max_score=0,
        score_ratio=0.0,
        status_counts={"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0},
        record_statuses={},
        core_pass_records=[],
    )
    report = _report(candidate, status="UNKNOWN", ambiguous=False, selected=False)
    output = _format_detection_report(report, "2026-02-02 12:00")
    assert "score n/a" in output
    assert "vars: tenant=acme" in output


def test_format_detection_report_includes_optional_bonus():
    candidate = DetectionCandidate(
        provider_id="dummy",
        provider_name="Dummy Provider",
        provider_version="1",
        inferred_variables={},
        score=10,
        max_score=10,
        score_ratio=1.0,
        status_counts={"PASS": 1, "WARN": 0, "FAIL": 0, "UNKNOWN": 0},
        record_statuses={"MX": "PASS"},
        core_pass_records=["MX"],
        optional_bonus=3,
    )
    report = _report(candidate, status="PASS", ambiguous=False, selected=True)
    output = _format_detection_report(report, "2026-02-02 12:00")

    assert "optional bonus: 3" in output


def test_build_detection_payload_without_selected_provider():
    report = _report(None, status="UNKNOWN", ambiguous=False, selected=False)
    payload = _build_detection_payload(report, "2026-02-02 12:00")
    assert payload["selected_provider"] is None


def test_provider_autoselect_ambiguous_returns_unknown(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    report = DetectionReport(
        domain="example.com",
        candidates=[_candidate("a"), _candidate("b")],
        selected=None,
        ambiguous=True,
        status="UNKNOWN",
        top_n=3,
    )
    import provider_check.cli as cli

    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "DNSChecker", object())

    code = main(["example.com", "--provider-autoselect", "--output", "text"])
    assert code == 3
    output = capsys.readouterr().out
    assert "provider detection report for domain example.com" in output


def test_provider_autoselect_runs_checks(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())

    code = main(["example.com", "--provider-autoselect", "--output", "text"])
    assert code == 0
    output = capsys.readouterr().out
    assert "provider detection report for domain example.com" in output
    assert "report for domain example.com" in output


def test_provider_autoselect_warn_exit(monkeypatch):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "WARN", "warn", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())

    code = main(
        [
            "example.com",
            "--provider-autoselect",
            "--output",
            "text",
            "--dmarc-subdomain-policy",
            "reject",
            "--dmarc-adkim",
            "s",
            "--dmarc-aspf",
            "s",
            "--dmarc-pct",
            "100",
        ]
    )
    assert code == 1


def test_provider_autoselect_human_fail(monkeypatch):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "FAIL", "fail", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())

    code = main(["example.com", "--provider-autoselect", "--output", "human"])
    assert code == 2


def test_provider_autoselect_json_statuses(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def __init__(self, status):
            self.status = status

        def run_checks(self):
            return [RecordCheck("MX", self.status, "status", {"found": ["mx"]})]

    for status, expected_code in [("PASS", 0), ("WARN", 1), ("FAIL", 2)]:
        monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker(status))
        code = main(
            [
                "example.com",
                "--provider-autoselect",
                "--output",
                "json",
                "--dmarc-subdomain-policy",
                "reject",
                "--dmarc-adkim",
                "s",
                "--dmarc-aspf",
                "s",
                "--dmarc-pct",
                "100",
            ]
        )
        assert code == expected_code
        payload = json.loads(capsys.readouterr().out)
        assert payload["report"]["provider"] == "Dummy Provider"


def test_provider_autoselect_json_unknown(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())
    monkeypatch.setattr(cli, "summarize_status", lambda _results: "UNKNOWN")

    code = main(["example.com", "--provider-autoselect", "--output", "json"])
    assert code == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "PASS"


def test_provider_autoselect_invalid_txt_records(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", "text", "--txt", "bad"])
    assert exc.value.code == 2
    assert "TXT record" in capsys.readouterr().err


def test_provider_autoselect_load_provider_error(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        cli, "load_provider_config", lambda _selection: (_ for _ in ()).throw(ValueError("nope"))
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", "text"])
    assert exc.value.code == 2
    assert "nope" in capsys.readouterr().err


def test_provider_autoselect_json_load_provider_error(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        cli, "load_provider_config", lambda _selection: (_ for _ in ()).throw(ValueError("nope"))
    )

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", "json"])
    assert exc.value.code == 2
    assert "nope" in capsys.readouterr().err


def test_provider_autoselect_json_invalid_txt_records(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-autoselect", "--output", "json", "--txt", "bad"])
    assert exc.value.code == 2
    assert "TXT record" in capsys.readouterr().err


def test_provider_autoselect_text_unknown(monkeypatch):
    _patch_fixed_datetime(monkeypatch)
    candidate = _candidate()
    report = _report(candidate)
    import provider_check.cli as cli

    provider = ProviderConfig(
        provider_id="dummy",
        name="Dummy Provider",
        version="1",
        mx=None,
        spf=None,
        dkim=None,
        txt=None,
        dmarc=None,
    )
    monkeypatch.setattr(cli, "detect_providers", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(cli, "load_provider_config", lambda _selection: provider)
    monkeypatch.setattr(cli, "resolve_provider_config", lambda prov, *_args, **_kwargs: prov)

    class _DummyChecker:
        def run_checks(self):
            return [RecordCheck("MX", "PASS", "ok", {"found": ["mx"]})]

    monkeypatch.setattr(cli, "DNSChecker", lambda *_args, **_kwargs: _DummyChecker())
    monkeypatch.setattr(cli, "summarize_status", lambda _results: "UNKNOWN")

    code = main(["example.com", "--provider-autoselect", "--output", "text"])
    assert code == 3


def test_provider_detect_flag_conflicts(monkeypatch, capsys):
    _patch_fixed_datetime(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-detect", "--provider-autoselect"])
    assert exc.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider", "dummy", "--provider-detect"])
    assert exc.value.code == 2
    assert "--provider cannot be used" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "--provider-detect", "--provider-var", "foo=bar"])
    assert exc.value.code == 2
    assert "--provider-var is not supported" in capsys.readouterr().err
