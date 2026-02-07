# Project Agent Instructions

## Environment and Tooling
- Always create `.venv` with exactly Python 3.11 using `python3.11 -m venv .venv` (do not use `python`, `python3`, or `./.venv/bin/python -m venv`).
- Before running project commands, verify the venv interpreter version with `./.venv/bin/python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"` and ensure it is `3.11`.
- If `.venv` is not Python 3.11, recreate it (`rm -rf .venv && python3.11 -m venv .venv`) and reinstall deps with `./.venv/bin/pip install ".[test]"`.
- Always run commands with explicit virtualenv executables (`./.venv/bin/python`, `./.venv/bin/pip`).
- If dependencies change in `pyproject.toml`, regenerate requirement files with `./.venv/bin/python scripts/update_requirements.py`.

## Required Validation Before Handoff
- Run `./.venv/bin/python -m black .`.
- Run `./.venv/bin/python -m pytest`.
- Run `./.venv/bin/python -m coverage run -m pytest`.
- Run `./.venv/bin/python -m coverage report -m --fail-under=100`.
- Run `./.venv/bin/python -m yamllint -c .yamllint src`.
- If checks fail because of environment issues, fix the environment and rerun; do not skip execution.
- For Markdown-only changes, you may skip formatting/lint/test runs.

## Testing and Coverage
- Add or update tests for every behavior change, including success and failure paths.
- Keep tests organized by feature area; split files before they become monolithic (around 350 lines).
- Reuse shared fixtures/factories from `tests/factories.py`, `tests/cli/conftest.py`, and `tests/provider_config/conftest.py` before adding local builders.
- Prefer `pytest.mark.parametrize` for repetitive input/expectation matrices.
- For negative-path tests, assert stable error/warning message text, not only indirect outcomes.
- When changing output or CLI behavior, ensure coverage includes all affected output formats and CLI flags.
- Prefer provider-agnostic fixtures in tests unless real provider config behavior is being validated.
- Avoid provider-specific names in tests unless real provider validation is required.

## Code and Documentation Conventions
- Use full Google-style docstrings (summary plus Args/Returns/Raises/Attributes where applicable).
- Keep modules small and focused; use per-feature submodules (for example, `checker/records/*`, `output/rows/*`, `provider_config/loader/parse/*`, `cli/*`) and re-export via package `__init__` files to preserve stable imports.
- For Jinja2 templates, keep output expressions visually readable inside control blocks by using spaced expressions (`{{ ... }}`).
- When editing Markdown tables, align columns so raw Markdown remains readable.
- Never remove entries from `.gitignore` without explicit user approval first.

## Provider Schema Consistency
- Treat `src/provider_check/provider_config/loader/parse/schema.py` as the single source of truth for provider record parser keys.
- Any provider schema change must update all of: `src/provider_check/provider_config/models.py`, affected parser modules under `src/provider_check/provider_config/loader/parse/`, and `tests/provider_config/test_parser_schema_contract.py`.
- Strict-mode behavior must be represented by structured fields (for example, `policy`) and not raw strict-only strings such as `required.record`.
- Schema-breaking changes require a Semantic Versioning major bump and matching updates to documentation/examples (including `README.md` and `src/provider_check/resources/providers/example_do_not_use.yaml`).

## Versioning and Commits
- Git commit messages must follow Conventional Commits 1.0.0 with required scope and body:
  `type(scope): short description`
  `long description`
- Versioning must follow Semantic Versioning 2.0.0.
