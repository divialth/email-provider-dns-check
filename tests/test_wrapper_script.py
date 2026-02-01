from pathlib import Path


def test_wrapper_script_exists_and_invokes_cli():
    script_path = Path(__file__).resolve().parents[1] / "provider-dns-check"
    content = script_path.read_text(encoding="utf-8")

    assert content.startswith("#!/usr/bin/env python3")
    assert "provider_check.cli" in content
    assert "sys.path.insert" in content
